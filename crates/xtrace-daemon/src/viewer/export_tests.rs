mod export_contract_tests {
    use super::*;
    use std::collections::BTreeSet;
    use xtrace_application::catalog_discovery::history::{
        CatalogExportOperationIdentity, CatalogExportReadError, CatalogExportRevision,
        CatalogExportScope, CatalogExportSnapshot, OperationView, RevisionEntry,
    };
    use xtrace_application::{CatalogChangeKind, CatalogSourceAvailability};
    use xtrace_domain::ContentHash;
    use xtrace_export::{ExportFormat, ExportRequest};

    fn snapshot() -> CatalogExportSnapshot {
        let view = OperationView {
            operation_id: OperationId::new(),
            operation_version_id: "fixture-version".to_owned(),
            application_component: "fixture".to_owned(),
            binding_key: "default".to_owned(),
            method: "GET".to_owned(),
            route_template: "/privateCatalogRoute/{id}".to_owned(),
            change_kind: CatalogChangeKind::Added,
            source_availability: CatalogSourceAvailability::Unverified,
            provenance: vec!["static_inferred".to_owned()],
            confidence_basis_points: 0,
            limitation_codes: Vec::new(),
            handlers: Vec::new(),
            handler_conflict: false,
            claim_count: 0,
            source_path: None,
            source_line: None,
            claims_available: true,
            claims: Vec::new(),
        };
        let mut second = view.clone();
        second.operation_id = OperationId::new();
        second.operation_version_id = "fixture-second-version".to_owned();
        second.route_template = "/".to_owned();
        let views = vec![view, second];
        CatalogExportSnapshot {
            observed_operation_id: None,
            revision: RevisionEntry {
                revision_id: xtrace_domain::CatalogRevisionId::new(),
                ordinal: 1,
                parent_revision_id: None,
                scope_digest: ContentHash::of_bytes(b"fixture"),
                source_revision_id: None,
                operation_count: 2,
                run_id: xtrace_domain::RunId::new(),
                created_at: "2026-11-25T00:00:00Z".to_owned(),
                completion: "complete",
                pack_status: "dev_unsigned",
            },
            catalog_identities: views
                .iter()
                .map(|view| CatalogExportOperationIdentity {
                    application_component: view.application_component.clone(),
                    binding_key: view.binding_key.clone(),
                    method: view.method.clone(),
                    route_template: view.route_template.clone(),
                    operation_version_id: view.operation_version_id.clone(),
                })
                .collect(),
            operations: views,
            linked_operation_ids: BTreeSet::new(),
        }
    }

    async fn start_exports<F>(reader: F) -> RunningViewer
    where
        F: Fn(
                ProjectId,
                CatalogExportRevision,
                CatalogExportScope,
                CatalogExportCancellation,
            ) -> Result<CatalogExportSnapshot, CatalogExportReadError>
            + Send
            + Sync
            + 'static,
    {
        let fixture = ReadFixture::default();
        let bound = BoundViewer::bind_with_catalog_exports(
            RecordingQueryService::new(fixture.clone()),
            ObservedEndpointQueryService::new(fixture.clone()),
            ProjectId::new(),
            reader,
        )
        .await
        .unwrap();
        let ready = bound.readiness();
        let host = ready.origin.strip_prefix("http://").unwrap().to_owned();
        let token = ready.url.rsplit_once("token=").unwrap().1.to_owned();
        let query_lane = bound.state.query_lane.clone();
        let (shutdown, receiver) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(bound.serve(async move {
            let _ = receiver.await;
        }));
        RunningViewer {
            host,
            origin: ready.origin,
            token,
            observed_calls: fixture.observed_calls,
            query_lane,
            shutdown,
            task,
        }
    }

    fn raw_post(viewer: &RunningViewer, cookie: &str, path: &str, body: &str) -> String {
        format!(
            "POST /api/v1/exports/{path} HTTP/1.1\r\n{}Cookie: {cookie}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            request_headers(&viewer.host, &viewer.origin),
            body.len()
        )
    }

    fn split_response(bytes: &[u8]) -> (&str, &[u8]) {
        let offset = bytes.windows(4).position(|bytes| bytes == b"\r\n\r\n").unwrap();
        (std::str::from_utf8(&bytes[..offset]).unwrap(), &bytes[offset + 4..])
    }

    async fn post(
        viewer: &RunningViewer,
        cookie: &str,
        path: &str,
        body: &serde_json::Value,
    ) -> (String, Vec<u8>) {
        let wire = wire_request(&viewer.host, &raw_post(viewer, cookie, path, &body.to_string()))
            .await
            .unwrap();
        let (headers, body) = split_response(&wire);
        (headers.to_owned(), body.to_vec())
    }

    fn selection(format: &str) -> serde_json::Value {
        serde_json::json!({"format":format,"yaml":false,"revision":"latest","scope":"all"})
    }

    // Python's independent ZIP reader checks CRC32 and resolves central-directory offsets.
    fn unzip(bytes: &[u8]) -> serde_json::Value {
        use std::io::Write as _;
        let mut child = std::process::Command::new("python3").args(["-c", r#"
import base64, io, json, sys, zipfile
with zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read())) as z:
    assert z.comment == b''
    print(json.dumps([{'name':i.filename,'bytes':base64.b64encode(z.read(i)).decode(),'date':i.date_time,'mode':i.external_attr>>16,'compression':i.compress_type,'extra':i.extra.hex(),'comment':i.comment.hex()} for i in z.infolist()]))
"#]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(bytes).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "independent ZIP verification failed");
        serde_json::from_slice(&output.stdout).unwrap()
    }

    #[tokio::test]
    async fn every_scope_and_format_saves_exact_cli_files_with_controlled_deterministic_attachments()
     {
        let fixture = snapshot();
        let current = fixture.clone();
        let viewer = start_exports(move |_, revision, scope, cancellation| {
            assert!(!cancellation.is_cancelled());
            if matches!(revision, CatalogExportRevision::Historical(id) if id != current.revision.revision_id) { return Err(CatalogExportReadError::RevisionNotFound); }
            if matches!(scope, CatalogExportScope::Operation(id) if id != current.operations[0].operation_id) { return Err(CatalogExportReadError::OperationNotFound); }
            let mut selected = current.clone();
            if let CatalogExportScope::Operation(id) = scope { selected.operations.retain(|view| view.operation_id == id); }
            Ok(selected)
        }).await;
        let cookie = authenticate(&viewer).await;
        for scope in ["all".to_owned(), fixture.operations[0].operation_id.to_string()] {
            for (format, yaml, filename, media_type) in [
                ("openapi", false, "openapi.json", "application/json"),
                ("openapi", true, "openapi.yaml", "application/yaml"),
                ("postman", false, "collection.postman.json", "application/json"),
                ("curl", false, "xtrace-curl.zip", "application/zip"),
                ("bundle", false, "xtrace-bundle.zip", "application/zip"),
            ] {
                let mut body = serde_json::json!({"format":format,"yaml":yaml,"revision":"latest","scope":scope});
                let (headers, bytes) = post(&viewer, &cookie, "preview", &body).await;
                assert!(headers.starts_with("HTTP/1.1 200"));
                let preview: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert!(!String::from_utf8(bytes).unwrap().contains("privateCatalogRoute"));
                assert_eq!(preview["download"]["filename"], filename);
                assert_eq!(preview["download"]["mediaType"], media_type);
                assert_eq!(preview["revisionId"], fixture.revision.revision_id.to_string());
                let expected_count = if scope == "all" { 2 } else { 1 };
                assert_eq!(preview["selectedOperations"], expected_count);
                assert_eq!(preview["emittedOperations"], expected_count);
                assert_eq!(preview["request"]["scope"], scope);
                body["approval"] = preview["approval"].clone();
                let (headers, saved) = post(&viewer, &cookie, "save", &body).await;
                assert!(headers.starts_with("HTTP/1.1 200"));
                assert!(headers.to_ascii_lowercase().contains("cache-control: no-store"));
                assert!(
                    headers.to_ascii_lowercase().contains(&format!("content-type: {media_type}"))
                );
                assert!(headers.contains(&format!("attachment; filename=\"{filename}\"")));
                let (_, second) = post(&viewer, &cookie, "save", &body).await;
                assert_eq!(saved, second);
                let input =
                    xtrace_export::catalog::prepare(&fixture.revision, &fixture.operations, &[]);
                let expected = xtrace_export::catalog::render(
                    &input,
                    &ExportRequest {
                        format: ExportFormat::parse(format).unwrap(),
                        yaml,
                        operation_ids: if scope == "all" {
                            None
                        } else {
                            Some(vec![scope.clone()])
                        },
                    },
                )
                .unwrap();
                if media_type == "application/zip" {
                    let actual = unzip(&saved);
                    assert_eq!(actual.as_array().unwrap().len(), expected.files.len());
                    for (actual, expected) in actual.as_array().unwrap().iter().zip(&expected.files)
                    {
                        assert_eq!(actual["name"], expected.path);
                        assert_eq!(
                            actual["bytes"],
                            base64::engine::general_purpose::STANDARD.encode(&expected.bytes)
                        );
                        assert_eq!(actual["date"], serde_json::json!([1980, 1, 1, 0, 0, 0]));
                        assert_eq!(actual["mode"], 0o100644);
                        assert_eq!(actual["compression"], 0);
                        assert_eq!(actual["extra"], "");
                        assert_eq!(actual["comment"], "");
                    }
                } else {
                    assert_eq!(saved, expected.files[0].bytes);
                }
            }
        }
        let _ = viewer.shutdown.send(());
        viewer.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn http_export_admission_rejects_cross_origin_client_session_and_unapproved_input_before_read()
     {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let viewer = start_exports(move |_, _, _, _| {
            count.fetch_add(1, Ordering::Relaxed);
            Ok(snapshot())
        })
        .await;
        let cookie = authenticate(&viewer).await;
        let body = selection("openapi").to_string();
        let raw = raw_post(&viewer, &cookie, "preview", &body);
        for (raw, status) in [
            (
                raw.replace(
                    &format!("Origin: {}", viewer.origin),
                    "Origin: http://example.invalid",
                ),
                403,
            ),
            (raw.replace("Sec-Fetch-Site: same-origin", "Sec-Fetch-Site: cross-site"), 403),
            (raw.replace("X-XTrace-Client: viewer-v1\r\n", ""), 403),
            (raw.replace(&format!("Cookie: {cookie}\r\n"), ""), 401),
            (raw.replace(&format!("Host: {}", viewer.host), "Host: localhost:1"), 403),
        ] {
            assert!(request(&viewer.host, &raw).await.starts_with(&format!("HTTP/1.1 {status}")));
        }
        let mut invalid = Vec::new();
        for (key, value) in [
            ("format", serde_json::json!("unknown")),
            ("scope", serde_json::json!("/private/input")),
            ("revision", serde_json::json!("bogus")),
            ("outputDir", serde_json::json!("/private/input")),
            ("approval", serde_json::Value::Null),
        ] {
            let mut body = selection("openapi");
            body[key] = value;
            invalid.push(body);
        }
        let mut invalid_yaml = selection("curl");
        invalid_yaml["yaml"] = true.into();
        invalid.push(invalid_yaml);
        for body in invalid {
            let (headers, bytes) = post(&viewer, &cookie, "preview", &body).await;
            assert!(headers.starts_with("HTTP/1.1 400"));
            assert!(!String::from_utf8(bytes).unwrap().contains("/private/input"));
        }
        let (headers, _) = post(&viewer, &cookie, "save", &selection("openapi")).await;
        assert!(headers.starts_with("HTTP/1.1 400"));
        let duplicate = r#"{"format":"openapi","format":"postman","yaml":false,"revision":"latest","scope":"all"}"#;
        assert!(
            request(&viewer.host, &raw_post(&viewer, &cookie, "preview", duplicate))
                .await
                .starts_with("HTTP/1.1 400")
        );
        let uppercase = serde_json::json!({"format":"openapi","yaml":false,"revision":"latest","scope":"all","approval":{"revisionId":xtrace_domain::CatalogRevisionId::new(),"digest":"A".repeat(64)}});
        assert!(post(&viewer, &cookie, "save", &uppercase).await.0.starts_with("HTTP/1.1 400"));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        let _ = viewer.shutdown.send(());
        viewer.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn same_revision_link_change_and_latest_change_require_refresh_without_download() {
        let current = Arc::new(std::sync::Mutex::new(snapshot()));
        let shared = current.clone();
        let viewer = start_exports(move |_, _, _, _| Ok(shared.lock().unwrap().clone())).await;
        let cookie = authenticate(&viewer).await;
        let mut body = selection("bundle");
        let (_, bytes) = post(&viewer, &cookie, "preview", &body).await;
        let preview: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        body["approval"] = preview["approval"].clone();
        {
            let mut current = current.lock().unwrap();
            let id = current.operations[0].operation_id;
            current.linked_operation_ids.insert(id);
        }
        let (headers, bytes) = post(&viewer, &cookie, "save", &body).await;
        assert!(headers.starts_with("HTTP/1.1 409"));
        assert!(!headers.contains("attachment"));
        assert!(String::from_utf8(bytes).unwrap().contains("XTR-EXPORT-STALE"));
        current.lock().unwrap().revision.revision_id = xtrace_domain::CatalogRevisionId::new();
        assert!(post(&viewer, &cookie, "save", &body).await.0.starts_with("HTTP/1.1 409"));
        let _ = viewer.shutdown.send(());
        viewer.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn store_errors_are_fixed_safe_problems_and_saturated_export_shares_the_query_lane() {
        for (error, status, code) in [
            (CatalogExportReadError::NoCatalog, 404, "NO-CATALOG"),
            (CatalogExportReadError::RevisionNotFound, 404, "REVISION"),
            (CatalogExportReadError::OperationNotFound, 404, "OPERATION"),
            (CatalogExportReadError::LimitExceeded, 413, "LIMIT"),
            (CatalogExportReadError::Corrupt, 422, "EVIDENCE"),
            (CatalogExportReadError::Busy, 503, "BUSY"),
            (CatalogExportReadError::Cancelled, 504, "DEADLINE"),
            (CatalogExportReadError::Unavailable, 503, "UNAVAILABLE"),
        ] {
            let viewer = start_exports(move |_, _, _, _| Err(error)).await;
            let cookie = authenticate(&viewer).await;
            let (headers, bytes) = post(&viewer, &cookie, "preview", &selection("openapi")).await;
            assert!(headers.starts_with(&format!("HTTP/1.1 {status}")));
            let problem: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(problem["code"], format!("XTR-EXPORT-{code}"));
            assert!(problem["requestId"].is_string());
            assert!(!String::from_utf8(bytes).unwrap().contains("SQLite"));
            let _ = viewer.shutdown.send(());
            viewer.task.await.unwrap().unwrap();
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let viewer = start_exports(move |_, _, _, _| {
            count.fetch_add(1, Ordering::Relaxed);
            Ok(snapshot())
        })
        .await;
        let cookie = authenticate(&viewer).await;
        let permits = viewer.query_lane.0.permits.clone().try_acquire_many_owned(2).unwrap();
        let (headers, bytes) = post(&viewer, &cookie, "preview", &selection("openapi")).await;
        assert!(headers.starts_with("HTTP/1.1 503"));
        assert!(String::from_utf8(bytes).unwrap().contains("XTR-EXPORT-BUSY"));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        drop(permits);
        assert!(
            post(&viewer, &cookie, "preview", &selection("openapi"))
                .await
                .0
                .starts_with("HTTP/1.1 200")
        );
        let _ = viewer.shutdown.send(());
        viewer.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn http_render_admission_refuses_oversized_input_without_artifact_metadata() {
        let mut large = snapshot();
        large.operations[0].route_template = "x".repeat(8 * 1024 * 1024);
        let viewer = start_exports(move |_, _, _, _| Ok(large.clone())).await;
        let cookie = authenticate(&viewer).await;
        let (headers, bytes) = post(&viewer, &cookie, "preview", &selection("bundle")).await;
        assert!(headers.starts_with("HTTP/1.1 413"));
        let problem: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(problem["code"], "XTR-EXPORT-LIMIT");
        assert!(problem.get("files").is_none());
        let _ = viewer.shutdown.send(());
        viewer.task.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn route_deadline_cancels_worker_and_retains_permit_until_actual_completion() {
        let (started, start) = tokio::sync::oneshot::channel();
        let started = std::sync::Mutex::new(Some(started));
        let (release, wait_release) = std::sync::mpsc::channel();
        let wait_release = std::sync::Mutex::new(wait_release);
        let fixture = ReadFixture::default();
        let bound = BoundViewer::bind_with_catalog_exports(
            RecordingQueryService::new(fixture.clone()),
            ObservedEndpointQueryService::new(fixture),
            ProjectId::new(),
            move |_, _, _, cancellation| {
                let sent = started.lock().unwrap().take().unwrap().send(cancellation.clone());
                assert!(sent.is_ok(), "request is listening");
                wait_release.lock().unwrap().recv().unwrap();
                Ok(snapshot())
            },
        )
        .await
        .unwrap();
        let state = bound.state.clone();
        let session = [23_u8; 32];
        state
            .sessions
            .lock()
            .await
            .insert(*blake3::hash(&session).as_bytes(), Instant::now() + Duration::from_secs(60));
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/exports/preview")
            .header(header::HOST, &state.host)
            .header(header::ORIGIN, &state.origin)
            .header("sec-fetch-site", "same-origin")
            .header("x-xtrace-client", "viewer-v1")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, format!("{SESSION_COOKIE}={}", URL_SAFE_NO_PAD.encode(session)))
            .body(Body::from(selection("openapi").to_string()))
            .unwrap();
        let mut app = router(state.clone());
        let request =
            tokio::spawn(async move { tower::Service::call(&mut app, request).await.unwrap() });
        let cancellation = start.await.unwrap();
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(14)).await;
        let response = request.await.unwrap();
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert!(cancellation.is_cancelled());
        assert_eq!(state.query_lane.0.active.load(Ordering::Acquire), 1);
        assert_eq!(state.query_lane.0.permits.available_permits(), 1);
        assert_eq!(state.export_slots.available_permits(), 1);
        let bytes = axum::body::to_bytes(response.into_body(), 2048).await.unwrap();
        assert!(std::str::from_utf8(&bytes).unwrap().contains("XTR-EXPORT-DEADLINE"));
        release.send(()).unwrap();
        tokio::time::resume();
        timeout(Duration::from_secs(2), state.query_lane.wait_drained()).await.unwrap();
        let permits = timeout(
            Duration::from_secs(2),
            state.query_lane.0.permits.clone().acquire_many_owned(2),
        )
        .await
        .unwrap()
        .unwrap();
        drop(permits);
        assert_eq!(state.query_lane.0.permits.available_permits(), 2);
        let slots =
            timeout(Duration::from_secs(2), state.export_slots.clone().acquire_many_owned(2))
                .await
                .unwrap()
                .unwrap();
        drop(slots);
        assert_eq!(state.export_slots.available_permits(), 2);
    }
    #[tokio::test]
    async fn sanitizer_refusal_and_missing_membership_never_disclose_catalog_text_or_attachment() {
        let mut unsafe_snapshot = snapshot();
        unsafe_snapshot.operations[0].route_template = "/xtrace-canary-private-export".to_owned();
        unsafe_snapshot.catalog_identities[0].route_template =
            unsafe_snapshot.operations[0].route_template.clone();
        let viewer = start_exports(move |_, _, _, _| Ok(unsafe_snapshot.clone())).await;
        let cookie = authenticate(&viewer).await;
        let (headers, bytes) = post(&viewer, &cookie, "preview", &selection("openapi")).await;
        assert!(headers.starts_with("HTTP/1.1 422"));
        assert!(!headers.contains("attachment"));
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("XTR-EXPORT-SANITIZER"));
        assert!(!text.contains("xtrace-canary"));
        let _ = viewer.shutdown.send(());
        viewer.task.await.unwrap().unwrap();
    }
    async fn direct_state() -> Arc<ViewerState<ReadFixture>> {
        let fixture = ReadFixture::default();
        let snapshot = snapshot();
        let bound = BoundViewer::bind_with_catalog_exports(
            RecordingQueryService::new(fixture.clone()),
            ObservedEndpointQueryService::new(fixture),
            ProjectId::new(),
            move |_, _, _, _| Ok(snapshot.clone()),
        )
        .await
        .unwrap();
        let state = bound.state.clone();
        state.sessions.lock().await.insert(
            *blake3::hash(&[23_u8; 32]).as_bytes(),
            Instant::now() + Duration::from_secs(60),
        );
        state
    }

    async fn direct_request(
        state: &Arc<ViewerState<ReadFixture>>,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Response {
        let request = Request::builder()
            .method(if body.is_some() { "POST" } else { "GET" })
            .uri(path)
            .header(header::HOST, &state.host)
            .header(header::ORIGIN, &state.origin)
            .header("sec-fetch-site", "same-origin")
            .header("x-xtrace-client", "viewer-v1")
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::COOKIE,
                format!("{SESSION_COOKIE}={}", URL_SAFE_NO_PAD.encode([23_u8; 32])),
            )
            .body(Body::from(body.map(|value| value.to_string()).unwrap_or_default()))
            .unwrap();
        tower::Service::call(&mut router(state.clone()), request).await.unwrap()
    }

    async fn approved_save(state: &Arc<ViewerState<ReadFixture>>) -> serde_json::Value {
        let body = selection("bundle");
        let response = direct_request(state, "/api/v1/exports/preview", Some(body.clone())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024).await.unwrap();
        let preview: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let mut body = body;
        body["approval"] = preview["approval"].clone();
        body
    }

    #[tokio::test]
    async fn export_slots_follow_transferred_cloned_and_sliced_attachment_bytes_until_last_drop() {
        use axum::body::HttpBody as _;
        let state = direct_state().await;
        let save = approved_save(&state).await;
        let first = direct_request(&state, "/api/v1/exports/save", Some(save.clone())).await;
        assert_eq!(first.status(), StatusCode::OK);
        let mut body = first.into_body();
        let frame = std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx))
            .await
            .unwrap()
            .unwrap();
        let bytes = frame.into_data().unwrap();
        assert!(bytes.starts_with(b"PK"));
        let cloned = bytes.clone();
        let sliced = cloned.slice(0..2);
        drop(body);
        assert_eq!(state.export_slots.available_permits(), 1);
        let second = direct_request(&state, "/api/v1/exports/save", Some(save.clone())).await;
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(state.export_slots.available_permits(), 0);
        let busy =
            direct_request(&state, "/api/v1/exports/preview", Some(selection("bundle"))).await;
        assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
        let problem = axum::body::to_bytes(busy.into_body(), 2048).await.unwrap();
        assert!(std::str::from_utf8(&problem).unwrap().contains("XTR-EXPORT-BUSY"));
        // Retained exports use no recording-query permits once computation ends.
        let read = direct_request(&state, "/api/v1/recordings", None).await;
        assert_eq!(read.status(), StatusCode::OK);
        drop(read);
        drop(bytes);
        drop(cloned);
        assert_eq!(
            state.export_slots.available_permits(),
            0,
            "a sliced transport chunk still owns the full backing allocation"
        );
        drop(sliced);
        assert_eq!(state.export_slots.available_permits(), 1);
        let replacement = direct_request(&state, "/api/v1/exports/save", Some(save)).await;
        assert_eq!(replacement.status(), StatusCode::OK);
        assert_eq!(state.export_slots.available_permits(), 0);
        drop(replacement);
        assert_eq!(state.export_slots.available_permits(), 1);
        drop(second);
        assert_eq!(state.export_slots.available_permits(), 2);
    }

    #[tokio::test]
    async fn export_slots_release_on_query_error_and_preserve_preview_byte_lifetime() {
        let state = direct_state().await;
        let mut invalid_save = selection("bundle");
        invalid_save["approval"] = serde_json::json!({"revisionId":xtrace_domain::CatalogRevisionId::new(),"digest":"0".repeat(64)});
        let stale = direct_request(&state, "/api/v1/exports/save", Some(invalid_save)).await;
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        assert_eq!(state.export_slots.available_permits(), 2);
        // Query-lane rejection also releases the independent export admission.
        let permits = state.query_lane.0.permits.clone().try_acquire_many_owned(2).unwrap();
        let busy =
            direct_request(&state, "/api/v1/exports/preview", Some(selection("bundle"))).await;
        assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(state.export_slots.available_permits(), 2);
        drop(permits);
        let preview =
            direct_request(&state, "/api/v1/exports/preview", Some(selection("bundle"))).await;
        assert_eq!(preview.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(preview.into_body(), 2 * 1024 * 1024).await.unwrap();
        assert_eq!(state.export_slots.available_permits(), 1);
        let clone = bytes.clone();
        drop(bytes);
        assert_eq!(state.export_slots.available_permits(), 1);
        drop(clone);
        assert_eq!(state.export_slots.available_permits(), 2);
    }
    #[tokio::test]
    async fn observed_scope_echoes_original_selector_and_exposes_only_resolved_catalog_id() {
        let original = snapshot();
        let catalog_id = original.operations[0].operation_id;
        let observed_id = OperationId::new();
        assert_ne!(observed_id, catalog_id);
        let viewer = start_exports(move |_, _, scope, _| {
            let mut selected = original.clone();
            match scope {
                CatalogExportScope::All => {}
                CatalogExportScope::Operation(id) => {
                    selected.operations.retain(|op| op.operation_id == id)
                }
                CatalogExportScope::ObservedOperation(id) if id == observed_id => {
                    selected.observed_operation_id = Some(id);
                    selected.operations.retain(|op| op.operation_id == catalog_id);
                    selected.linked_operation_ids.insert(catalog_id);
                }
                CatalogExportScope::ObservedOperation(_) => {
                    return Err(CatalogExportReadError::OperationNotFound);
                }
            }
            if selected.operations.is_empty() {
                return Err(CatalogExportReadError::OperationNotFound);
            }
            Ok(selected)
        })
        .await;
        let cookie = authenticate(&viewer).await;
        let mut body = selection("bundle");
        body["scope"] = format!("observed:{observed_id}").into();
        let (headers, bytes) = post(&viewer, &cookie, "preview", &body).await;
        assert!(headers.starts_with("HTTP/1.1 200"));
        let preview: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(preview["request"]["scope"], format!("observed:{observed_id}"));
        assert_eq!(preview["catalogOperationId"], catalog_id.to_string());
        assert_eq!(preview["selectedOperations"], 1);
        body["approval"] = preview["approval"].clone();
        assert!(post(&viewer, &cookie, "save", &body).await.0.starts_with("HTTP/1.1 200"));
        body["scope"] = catalog_id.to_string().into();
        assert!(post(&viewer, &cookie, "save", &body).await.0.starts_with("HTTP/1.1 409"));
        let mut missing = selection("bundle");
        missing["scope"] = format!("observed:{}", OperationId::new()).into();
        assert!(post(&viewer, &cookie, "preview", &missing).await.0.starts_with("HTTP/1.1 404"));
        let mut malformed = selection("bundle");
        malformed["scope"] = "observed:not-an-id".into();
        assert!(post(&viewer, &cookie, "preview", &malformed).await.0.starts_with("HTTP/1.1 400"));
        for noncanonical in [
            "ABCDEF01-2345-6789-ABCD-EF0123456789".to_owned(),
            observed_id.to_string().replace('-', ""),
            format!("{{{observed_id}}}"),
            format!("urn:uuid:{observed_id}"),
        ] {
            malformed["scope"] = format!("observed:{noncanonical}").into();
            for action in ["preview", "save"] {
                if action == "save" {
                    malformed["approval"] = preview["approval"].clone();
                } else {
                    malformed.as_object_mut().unwrap().remove("approval");
                }
                assert!(post(&viewer, &cookie, action, &malformed)
                    .await
                    .0
                    .starts_with("HTTP/1.1 400"));
            }
        }
        let (_, all) = post(&viewer, &cookie, "preview", &selection("bundle")).await;
        let all: serde_json::Value = serde_json::from_slice(&all).unwrap();
        assert!(all["catalogOperationId"].is_null());
        let _ = viewer.shutdown.send(());
        viewer.task.await.unwrap().unwrap();
    }
}
