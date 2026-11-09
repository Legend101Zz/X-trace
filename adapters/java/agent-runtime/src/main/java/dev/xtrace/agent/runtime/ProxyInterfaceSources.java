package dev.xtrace.agent.runtime;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.jar.asm.Type;
import net.bytebuddy.jar.asm.signature.SignatureReader;
import net.bytebuddy.jar.asm.signature.SignatureVisitor;

/**
 * Declaration extents for abstract interface methods, whose class files have no line table.
 * Only unambiguous signatures in the observed SourceFile are used, with OBSERVED_UNATTESTED
 * binding. This is source declaration metadata, never an executing line or build attestation.
 */
final class ProxyInterfaceSources {
  private static final Map<ClassLoader, Map<String, Map<String, SourceAttestation.SourceInfo>>>
      LOADERS = new WeakHashMap<>();

  private ProxyInterfaceSources() {}

  static void observe(ClassLoader loader, String name, byte[] bytes, ApplicationScope scope) {
    observe(loader, name, bytes, scope, () -> {});
  }

  /** Per-observation seam for a source change between identity and declaration reads. */
  static void observe(ClassLoader loader, String name, byte[] bytes, ApplicationScope scope,
      Runnable afterIdentity) {
    observe(loader, name, bytes, scope, afterIdentity, ConfinedSourceFiles::read);
  }

  static void observe(ClassLoader loader, String name, byte[] bytes, ApplicationScope scope,
      Runnable afterIdentity, ConfinedSourceFiles.Reader sourceReader) {
    if (loader == null || bytes.length > 8 * 1024 * 1024) return;
    try {
      ClassReader reader = new ClassReader(bytes);
      if ((reader.getAccess() & Opcodes.ACC_INTERFACE) == 0) return;
      SourceIdentity.ClassFacts facts = SourceIdentity.parse(name, bytes);
      facts.resolve(scope.sourceRoots(), scope.sourceBase(), sourceReader);
      if (facts.path() == null || facts.hash() == null) return;
      afterIdentity.run();
      ConfinedSourceFiles.Source source = sourceReader.read(scope.sourceBase(), facts.path());
      if (source == null) return;
      byte[] content = source.bytes();
      if (!java.util.Arrays.equals(facts.hash(), SourceAttestation.blake3Of(content))) return;
      Map<String, SourceAttestation.SourceInfo> methods = new HashMap<>();
      String text = new String(content, StandardCharsets.UTF_8);
      List<Token> tokens = tokenize(text);
      reader.accept(new ClassVisitor(Opcodes.ASM9) {
        private final Map<String, String> typeVariables = new HashMap<>();

        @Override
        public void visit(int version, int access, String name, String signature,
            String parent, String[] interfaces) {
          bounds(signature, typeVariables);
        }

        @Override
        public MethodVisitor visitMethod(int access, String method, String descriptor,
            String signature, String[] exceptions) {
          if ((access & (Opcodes.ACC_SYNTHETIC | Opcodes.ACC_BRIDGE | Opcodes.ACC_STATIC)) != 0)
            return null;
          Map<String, String> variables = new HashMap<>(typeVariables);
          bounds(signature, variables);
          int[] range = declaration(tokens, name, method, Type.getArgumentTypes(descriptor), variables);
          if (range != null) methods.put(method + descriptor, new SourceAttestation.SourceInfo(
              facts.path(), range[0], range[1], facts.hash(), SourceIdentity.OBSERVED_UNATTESTED));
          return null;
        }
      }, ClassReader.SKIP_CODE);
      synchronized (LOADERS) {
        var classes = LOADERS.computeIfAbsent(loader, ignored -> new HashMap<>());
        if (classes.size() < 20_000) classes.put(name.replace('/', '.'), Map.copyOf(methods));
      }
    } catch (Exception | LinkageError ignored) {
      // Missing, ambiguous or unreadable declarations remain explicitly unavailable.
    }
  }

  static SourceAttestation.SourceInfo lookup(Method method) {
    String descriptor = Type.getMethodDescriptor(method);
    SourceAttestation.SourceInfo debug = SourceIdentity.lookup(
        method.getDeclaringClass(), method.getName(), descriptor);
    if (debug.path() != null) return debug;
    synchronized (LOADERS) {
      var classes = LOADERS.get(method.getDeclaringClass().getClassLoader());
      var methods = classes == null ? null : classes.get(method.getDeclaringClass().getName());
      return methods == null ? debug : methods.getOrDefault(method.getName() + descriptor, debug);
    }
  }

  private record Token(String text, int line) {}

  /** Erased bounds come from the observed class signature, never from loading a source type. */
  private static void bounds(String signature, Map<String, String> variables) {
    if (signature == null) return;
    new SignatureReader(signature).accept(new SignatureVisitor(Opcodes.ASM9) {
      private String variable;
      @Override
      public void visitFormalTypeParameter(String name) {
        variable = name;
        variables.remove(name); // A method type variable may shadow one from its interface.
      }
      @Override
      public SignatureVisitor visitClassBound() { return bound(); }
      @Override
      public SignatureVisitor visitInterfaceBound() { return bound(); }
      private SignatureVisitor bound() {
        String name = variable;
        return new SignatureVisitor(Opcodes.ASM9) {
          @Override
          public void visitClassType(String type) {
            variables.putIfAbsent(name, type.replace('/', '.').replace('$', '.'));
          }
          @Override
          public void visitTypeVariable(String type) {
            if (variables.containsKey(type)) variables.putIfAbsent(name, variables.get(type));
          }
          @Override
          public SignatureVisitor visitTypeArgument(char wildcard) { return ignoredSignature(); }
        };
      }
      @Override public SignatureVisitor visitSuperclass() { return ignoredSignature(); }
      @Override public SignatureVisitor visitInterface() { return ignoredSignature(); }
      @Override public SignatureVisitor visitParameterType() { return ignoredSignature(); }
      @Override public SignatureVisitor visitReturnType() { return ignoredSignature(); }
      @Override public SignatureVisitor visitExceptionType() { return ignoredSignature(); }
    });
  }

  private static SignatureVisitor ignoredSignature() {
    return new SignatureVisitor(Opcodes.ASM9) {};
  }

  private static List<Token> tokenize(String text) {
    List<Token> tokens = new ArrayList<>();
    int line = 1;
    // Unicode escapes are processed before Java lexing and can introduce comments/newlines.
    // Leave those files unavailable rather than pretending a lexical scan resolved them.
    if (text.contains("\\u")) return List.of();
    for (int i = 0; i < text.length();) {
      if (tokens.size() >= 65_536) return List.of();
      char c = text.charAt(i);
      if (Character.isWhitespace(c)) {
        if (c == '\n') line++;
        i++;
      } else if (text.startsWith("//", i)) {
        while (i < text.length() && text.charAt(i) != '\n') i++;
      } else if (text.startsWith("/*", i)) {
        i += 2;
        while (i < text.length() && !text.startsWith("*/", i)) {
          if (text.charAt(i++) == '\n') line++;
        }
        i = Math.min(text.length(), i + 2);
      } else if (c == '\'' || c == '"') {
        boolean block = text.startsWith("\"\"\"", i);
        String end = block ? "\"\"\"" : Character.toString(c);
        i += end.length();
        while (i < text.length() && !text.startsWith(end, i)) {
          if (text.charAt(i) == '\\' && i + 1 < text.length()) i++;
          if (text.charAt(i++) == '\n') line++;
        }
        i = Math.min(text.length(), i + end.length());
      } else {
        int start = i++;
        if (Character.isJavaIdentifierStart(c)) {
          while (i < text.length() && Character.isJavaIdentifierPart(text.charAt(i))) i++;
        } else if (text.startsWith("...", start)) {
          i = start + 3;
        }
        tokens.add(new Token(text.substring(start, i), line));
      }
    }
    return tokens;
  }

  /** Conservative lexical matching: ambiguous overloads and unsupported syntax have no range. */
  private static int[] declaration(List<Token> tokens, String internalName, String method,
      Type[] parameters, Map<String, String> variables) {
    String simple = internalName.substring(Math.max(internalName.lastIndexOf('/'),
        internalName.lastIndexOf('$')) + 1);
    int body = -1;
    for (int i = 0; i + 2 < tokens.size(); i++) {
      if (tokens.get(i).text.equals("interface") && tokens.get(i + 1).text.equals(simple)) {
        if (body != -1) return null;
        int j = i + 2;
        while (j < tokens.size() && !tokens.get(j).text.equals("{")) j++;
        body = j;
      }
    }
    if (body < 0) return null;
    int depth = 1;
    int parentheses = 0;
    int[] found = null;
    for (int i = body + 1; i + 1 < tokens.size() && depth > 0; i++) {
      String token = tokens.get(i).text;
      String previous = tokens.get(i - 1).text;
      if (depth == 1 && parentheses == 0 && token.equals(method)
          && tokens.get(i + 1).text.equals("(")
          && !previous.equals("new")
          && (Character.isJavaIdentifierStart(previous.charAt(0))
              || previous.equals("]") || previous.equals(">"))) {
        int end = i + 2;
        int nesting = 1;
        while (end < tokens.size() && nesting > 0) {
          String t = tokens.get(end).text;
          if (t.equals("(")) nesting++;
          if (t.equals(")")) nesting--;
          end++;
        }
        if (nesting == 0 && matches(tokens.subList(i + 2, end - 1), parameters, variables)) {
          int terminator = end;
          while (terminator < tokens.size()
              && !List.of(";", "{", "}", "=").contains(tokens.get(terminator).text)) terminator++;
          if (terminator < tokens.size()
              && List.of(";", "{").contains(tokens.get(terminator).text)) {
            if (found != null) return null;
            found = new int[] {tokens.get(i).line, tokens.get(terminator).line};
          }
        }
      }
      if (token.equals("{")) depth++;
      if (token.equals("}")) depth--;
      if (token.equals("(")) parentheses++;
      if (token.equals(")")) parentheses--;
    }
    return found;
  }

  private static boolean matches(List<Token> tokens, Type[] expected, Map<String, String> variables) {
    List<String> types = new ArrayList<>();
    StringBuilder parameter = new StringBuilder();
    int generic = 0;
    for (int index = 0; index < tokens.size(); index++) {
      String t = tokens.get(index).text;
      if (t.equals("@")) {
        // Parameter annotations are not part of the erased signature.
        index++;
        while (index + 2 < tokens.size() && tokens.get(index + 1).text.equals(".")) index += 2;
        if (index + 1 < tokens.size() && tokens.get(index + 1).text.equals("(")) {
          index += 2;
          int nesting = 1;
          for (; index < tokens.size() && nesting > 0; index++) {
            if (tokens.get(index).text.equals("(")) nesting++;
            if (tokens.get(index).text.equals(")")) nesting--;
          }
          if (nesting != 0) return false;
          index--;
        }
        continue;
      }
      if (t.equals("<")) { generic++; continue; }
      if (t.equals(">")) { generic--; continue; }
      if (generic > 0 || t.equals("final")) continue;
      if (t.equals(",")) {
        types.add(parameter.toString());
        parameter.setLength(0);
      } else {
        parameter.append(t).append(' ');
      }
    }
    if (!parameter.isEmpty()) types.add(parameter.toString());
    if (types.size() != expected.length) return false;
    for (int i = 0; i < expected.length; i++) {
      String source = types.get(i).trim();
      int split = source.lastIndexOf(' ');
      if (split < 0) return false;
      source = source.substring(0, split).replace(" ", "").replace("...", "[]");
      int array = source.indexOf('[');
      String raw = array < 0 ? source : source.substring(0, array);
      if (variables.containsKey(raw)) {
        source = variables.get(raw) + (array < 0 ? "" : source.substring(array));
      }
      String binary = expected[i].getClassName().replace('$', '.');
      String simple = binary.substring(binary.lastIndexOf('.') + 1);
      if (!source.equals(binary) && !source.equals(simple)) return false;
    }
    return true;
  }
}
