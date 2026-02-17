package io.phasetwo.keycloak.admin.resource;

import io.phasetwo.keycloak.admin.Http;
import io.phasetwo.keycloak.admin.JsonSerialization;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HEAD;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Supplier;
import org.apache.http.HttpHeaders;
import org.apache.http.client.HttpClient;
import org.apache.http.entity.StringEntity;

public final class ResourceProxyFactory {

  private ResourceProxyFactory() {}

  public static <T> T create(
      Class<T> resourceInterface,
      String baseUrl,
      HttpClient client,
      Supplier<String> tokenSupplier,
      Consumer<String> tokenInvalidator) {
    Objects.requireNonNull(resourceInterface, "resourceInterface");
    Objects.requireNonNull(baseUrl, "baseUrl");
    Objects.requireNonNull(client, "client");

    InvocationHandler handler =
        new ResourceInvocationHandler(
            resourceInterface, normalizeBaseUrl(baseUrl), client, tokenSupplier, tokenInvalidator);
    return resourceInterface.cast(
        Proxy.newProxyInstance(
            resourceInterface.getClassLoader(), new Class<?>[] {resourceInterface}, handler));
  }

  private static String normalizeBaseUrl(String baseUrl) {
    if (baseUrl.endsWith("/")) {
      return baseUrl.substring(0, baseUrl.length() - 1);
    }
    return baseUrl;
  }

  private static final class ResourceInvocationHandler implements InvocationHandler {
    private final Class<?> resourceInterface;
    private final String interfacePath;
    private final String baseUrl;
    private final HttpClient client;
    private final Supplier<String> tokenSupplier;
    private final Consumer<String> tokenInvalidator;

    private ResourceInvocationHandler(
        Class<?> resourceInterface,
        String baseUrl,
        HttpClient client,
        Supplier<String> tokenSupplier,
        Consumer<String> tokenInvalidator) {
      this.resourceInterface = resourceInterface;
      this.interfacePath = pathValue(resourceInterface.getAnnotation(Path.class));
      this.baseUrl = baseUrl;
      this.client = client;
      this.tokenSupplier = tokenSupplier;
      this.tokenInvalidator = tokenInvalidator;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      if (method.getDeclaringClass() == Object.class) {
        return invokeObjectMethod(proxy, method, args);
      }

      String httpMethod = resolveHttpMethod(method);
      String methodPath = pathValue(method.getAnnotation(Path.class));

      if (httpMethod == null && method.getReturnType().isInterface()) {
        String nestedPath =
            replacePathParams(
                joinPaths(joinPaths(baseUrl, interfacePath), methodPath), method, args);
        return ResourceProxyFactory.create(
            method.getReturnType(), nestedPath, client, tokenSupplier, tokenInvalidator);
      }

      if (httpMethod == null) {
        throw new IllegalStateException(
            "No HTTP method annotation present on "
                + resourceInterface.getName()
                + "#"
                + method.getName());
      }

      String url =
          replacePathParams(joinPaths(joinPaths(baseUrl, interfacePath), methodPath), method, args);
      RequestParts requestParts = extractRequestParts(method, args);
      return invokeHttp(method, httpMethod, url, requestParts);
    }

    private Object invokeHttp(
        Method method, String httpMethod, String url, RequestParts requestParts)
        throws IOException {
      Http request = newRequest(httpMethod, url);

      String token = tokenSupplier == null ? null : tokenSupplier.get();
      if (token != null && !token.isBlank()) {
        request.auth(token);
      }

      String accept = resolveProduces(method);
      if (accept != null && !accept.isBlank()) {
        request.header(HttpHeaders.ACCEPT, accept);
      }

      String contentType = resolveConsumes(method);

      for (Map.Entry<String, String> query : requestParts.queryParams.entrySet()) {
        request.param(query.getKey(), query.getValue());
      }

      if (!requestParts.formParams.isEmpty()) {
        for (Map.Entry<String, String> form : requestParts.formParams.entrySet()) {
          request.param(form.getKey(), form.getValue());
        }
      } else if (requestParts.body != null) {
        if (MediaType.TEXT_PLAIN.equals(contentType)) {
          request.entity(
              new StringEntity(String.valueOf(requestParts.body), StandardCharsets.UTF_8));
        } else {
          if (contentType != null && !contentType.isBlank()) {
            request.header(HttpHeaders.CONTENT_TYPE, contentType);
          }
          request.json(requestParts.body);
        }
      } else if (isWriteMethod(httpMethod)) {
        request.entity(new StringEntity("", StandardCharsets.UTF_8));
      }

      try (Http.Response response = request.asResponse()) {
        if (response.getStatus() == 401
            && tokenInvalidator != null
            && token != null
            && !token.isBlank()) {
          tokenInvalidator.accept(token);
          return retryWithFreshToken(method, httpMethod, url, requestParts);
        }
        return toReturnValue(method, response);
      }
    }

    private Object retryWithFreshToken(
        Method method, String httpMethod, String url, RequestParts requestParts)
        throws IOException {
      Http retry = newRequest(httpMethod, url);
      String freshToken = tokenSupplier == null ? null : tokenSupplier.get();
      if (freshToken != null && !freshToken.isBlank()) {
        retry.auth(freshToken);
      }

      String accept = resolveProduces(method);
      if (accept != null && !accept.isBlank()) {
        retry.header(HttpHeaders.ACCEPT, accept);
      }

      String contentType = resolveConsumes(method);
      for (Map.Entry<String, String> query : requestParts.queryParams.entrySet()) {
        retry.param(query.getKey(), query.getValue());
      }
      if (!requestParts.formParams.isEmpty()) {
        for (Map.Entry<String, String> form : requestParts.formParams.entrySet()) {
          retry.param(form.getKey(), form.getValue());
        }
      } else if (requestParts.body != null) {
        if (MediaType.TEXT_PLAIN.equals(contentType)) {
          retry.entity(new StringEntity(String.valueOf(requestParts.body), StandardCharsets.UTF_8));
        } else {
          if (contentType != null && !contentType.isBlank()) {
            retry.header(HttpHeaders.CONTENT_TYPE, contentType);
          }
          retry.json(requestParts.body);
        }
      } else if (isWriteMethod(httpMethod)) {
        retry.entity(new StringEntity("", StandardCharsets.UTF_8));
      }

      try (Http.Response response = retry.asResponse()) {
        return toReturnValue(method, response);
      }
    }

    private Http newRequest(String httpMethod, String url) {
      return switch (httpMethod) {
        case "GET" -> Http.doGet(url, client);
        case "POST" -> Http.doPost(url, client);
        case "PUT" -> Http.doPut(url, client);
        case "DELETE" -> Http.doDelete(url, client);
        case "PATCH" -> Http.doPatch(url, client);
        case "HEAD" -> Http.doHead(url, client);
        default -> throw new IllegalStateException("Unsupported HTTP method " + httpMethod);
      };
    }

    private Object toReturnValue(Method method, Http.Response response) throws IOException {
      int status = response.getStatus();
      if (status >= 400) {
        if (status == 400) {
          throw new BadRequestException(buildErrorMessage(status, response.asString()));
        }
        throw new WebApplicationException(buildErrorMessage(status, response.asString()), status);
      }

      Class<?> returnType = method.getReturnType();
      if (returnType == Void.TYPE || returnType == Void.class) {
        return null;
      }
      if (Response.class.isAssignableFrom(returnType)) {
        org.apache.http.entity.ContentType contentType = response.getContentType();
        return new SimpleResponse(
            response.getStatus(),
            response.getAllHeaders(),
            response.asString(),
            contentType == null ? null : contentType.getMimeType());
      }

      String body = response.asString();
      if (body == null || body.isBlank()) {
        return null;
      }
      if (returnType == String.class) {
        return body;
      }
      return JsonSerialization.mapper.readValue(
          body,
          JsonSerialization.mapper.getTypeFactory().constructType(method.getGenericReturnType()));
    }

    private static String buildErrorMessage(int status, String body) {
      if (body == null || body.isBlank()) {
        return "HTTP " + status;
      }
      return "HTTP " + status + ": " + body;
    }

    private RequestParts extractRequestParts(Method method, Object[] args) {
      RequestParts requestParts = new RequestParts();
      if (args == null || args.length == 0) {
        return requestParts;
      }

      Parameter[] parameters = method.getParameters();
      for (int i = 0; i < parameters.length; i++) {
        Parameter parameter = parameters[i];
        Object arg = args[i];
        Annotation[] annotations = parameter.getAnnotations();
        boolean annotated = false;
        for (Annotation annotation : annotations) {
          if (annotation instanceof PathParam || annotation instanceof DefaultValue) {
            annotated = true;
            continue;
          }
          if (annotation instanceof QueryParam queryParam) {
            annotated = true;
            addParam(requestParts.queryParams, queryParam.value(), arg);
          } else if (annotation instanceof FormParam formParam) {
            annotated = true;
            addParam(requestParts.formParams, formParam.value(), arg);
          }
        }
        if (!annotated) {
          requestParts.body = arg;
        }
      }
      return requestParts;
    }

    private static void addParam(Map<String, String> target, String key, Object value) {
      if (value == null) {
        return;
      }
      if (value instanceof Collection<?> values) {
        List<String> asStrings = new ArrayList<>();
        for (Object v : values) {
          if (v != null) {
            asStrings.add(String.valueOf(v));
          }
        }
        if (!asStrings.isEmpty()) {
          target.put(key, String.join(",", asStrings));
        }
        return;
      }
      target.put(key, String.valueOf(value));
    }

    private static String replacePathParams(String path, Method method, Object[] args) {
      if (args == null || args.length == 0) {
        return path;
      }
      Parameter[] parameters = method.getParameters();
      String resolved = path;
      for (int i = 0; i < parameters.length; i++) {
        for (Annotation annotation : parameters[i].getAnnotations()) {
          if (annotation instanceof PathParam pathParam) {
            Object value = args[i];
            if (value == null) {
              throw new IllegalArgumentException(
                  "Path parameter '"
                      + pathParam.value()
                      + "' is null for method "
                      + method.getName());
            }
            resolved =
                resolved.replaceAll(
                    "\\{" + pathParam.value() + "(?::[^}]*)?\\}",
                    java.util.regex.Matcher.quoteReplacement(String.valueOf(value)));
          }
        }
      }
      return resolved;
    }

    private String resolveConsumes(Method method) {
      Consumes consumes = method.getAnnotation(Consumes.class);
      if (consumes == null) {
        consumes = resourceInterface.getAnnotation(Consumes.class);
      }
      if (consumes == null || consumes.value().length == 0) {
        return MediaType.APPLICATION_JSON;
      }
      return consumes.value()[0];
    }

    private String resolveProduces(Method method) {
      Produces produces = method.getAnnotation(Produces.class);
      if (produces == null) {
        produces = resourceInterface.getAnnotation(Produces.class);
      }
      if (produces == null || produces.value().length == 0) {
        return MediaType.APPLICATION_JSON;
      }
      return produces.value()[0];
    }

    private static boolean isWriteMethod(String httpMethod) {
      return "POST".equals(httpMethod) || "PUT".equals(httpMethod) || "PATCH".equals(httpMethod);
    }

    private static String resolveHttpMethod(Method method) {
      if (method.isAnnotationPresent(GET.class)) {
        return "GET";
      }
      if (method.isAnnotationPresent(POST.class)) {
        return "POST";
      }
      if (method.isAnnotationPresent(PUT.class)) {
        return "PUT";
      }
      if (method.isAnnotationPresent(DELETE.class)) {
        return "DELETE";
      }
      if (method.isAnnotationPresent(PATCH.class)) {
        return "PATCH";
      }
      if (method.isAnnotationPresent(HEAD.class)) {
        return "HEAD";
      }
      return null;
    }

    private static String pathValue(Path path) {
      if (path == null || path.value().isBlank()) {
        return "";
      }
      return path.value();
    }

    private static String joinPaths(String left, String right) {
      if (right == null || right.isBlank()) {
        return left;
      }
      if (left.endsWith("/") && right.startsWith("/")) {
        return left + right.substring(1);
      }
      if (!left.endsWith("/") && !right.startsWith("/")) {
        return left + "/" + right;
      }
      return left + right;
    }

    private Object invokeObjectMethod(Object proxy, Method method, Object[] args) {
      String name = method.getName();
      if ("toString".equals(name) && method.getParameterCount() == 0) {
        return "ResourceProxy(" + resourceInterface.getName() + ")";
      }
      if ("hashCode".equals(name) && method.getParameterCount() == 0) {
        return System.identityHashCode(proxy);
      }
      if ("equals".equals(name) && method.getParameterCount() == 1) {
        return proxy == args[0];
      }
      throw new IllegalStateException("Unsupported Object method: " + name);
    }
  }

  private static final class RequestParts {
    private final Map<String, String> queryParams = new LinkedHashMap<>();
    private final Map<String, String> formParams = new LinkedHashMap<>();
    private Object body;
  }
}
