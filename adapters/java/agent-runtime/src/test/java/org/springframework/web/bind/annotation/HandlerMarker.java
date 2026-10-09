package org.springframework.web.bind.annotation;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/** Test-only stand-in for a web binding annotation: the matcher keys on the package prefix. */
@Retention(RetentionPolicy.RUNTIME)
public @interface HandlerMarker {}
