package io.phasetwo.keycloak.admin.resource;

import io.phasetwo.keycloak.admin.JsonSerialization;
import jakarta.ws.rs.core.EntityTag;
import jakarta.ws.rs.core.GenericType;
import jakarta.ws.rs.core.Link;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.apache.http.Header;

final class SimpleResponse extends Response {

  private final int status;
  private final StatusType statusType;
  private final String entity;
  private final String contentType;
  private final MultivaluedMap<String, Object> headers;

  SimpleResponse(int status, Header[] responseHeaders, String entity, String contentType) {
    this.status = status;
    this.statusType = toStatusType(status);
    this.entity = entity;
    this.contentType = contentType;
    this.headers = new MultivaluedHashMap<>();
    if (responseHeaders != null) {
      for (Header header : responseHeaders) {
        headers.add(header.getName(), header.getValue());
      }
    }
  }

  @Override
  public int getStatus() {
    return status;
  }

  @Override
  public StatusType getStatusInfo() {
    return statusType;
  }

  @Override
  public Object getEntity() {
    return entity;
  }

  @Override
  public <T> T readEntity(Class<T> entityType) {
    return readEntity(entityType, new Annotation[0]);
  }

  @Override
  public <T> T readEntity(GenericType<T> entityType) {
    return readEntity(entityType, new Annotation[0]);
  }

  @Override
  @SuppressWarnings("unchecked")
  public <T> T readEntity(Class<T> entityType, Annotation[] annotations) {
    if (entity == null) {
      return null;
    }
    if (entityType == String.class) {
      return (T) entity;
    }
    try {
      return JsonSerialization.mapper.readValue(entity, entityType);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to read response entity", e);
    }
  }

  @Override
  public <T> T readEntity(GenericType<T> entityType, Annotation[] annotations) {
    if (entity == null) {
      return null;
    }
    try {
      return JsonSerialization.mapper.readValue(
          entity, JsonSerialization.mapper.getTypeFactory().constructType(entityType.getType()));
    } catch (IOException e) {
      throw new IllegalStateException("Failed to read response entity", e);
    }
  }

  @Override
  public boolean hasEntity() {
    return entity != null && !entity.isBlank();
  }

  @Override
  public boolean bufferEntity() {
    return true;
  }

  @Override
  public void close() {}

  @Override
  public MediaType getMediaType() {
    if (contentType == null || contentType.isBlank()) {
      return null;
    }
    return MediaType.valueOf(contentType);
  }

  @Override
  public Locale getLanguage() {
    return null;
  }

  @Override
  public int getLength() {
    return entity == null ? -1 : entity.length();
  }

  @Override
  public Set<String> getAllowedMethods() {
    String allow = getHeaderString("Allow");
    if (allow == null || allow.isBlank()) {
      return Collections.emptySet();
    }
    Set<String> methods = new LinkedHashSet<>();
    for (String part : allow.split(",")) {
      String method = part.trim();
      if (!method.isEmpty()) {
        methods.add(method);
      }
    }
    return methods;
  }

  @Override
  public Map<String, NewCookie> getCookies() {
    return Collections.emptyMap();
  }

  @Override
  public EntityTag getEntityTag() {
    String etag = getHeaderString("ETag");
    return etag == null ? null : new EntityTag(etag);
  }

  @Override
  public Date getDate() {
    return null;
  }

  @Override
  public Date getLastModified() {
    return null;
  }

  @Override
  public URI getLocation() {
    String location = getHeaderString("Location");
    return location == null ? null : URI.create(location);
  }

  @Override
  public Set<Link> getLinks() {
    return Collections.emptySet();
  }

  @Override
  public boolean hasLink(String relation) {
    return false;
  }

  @Override
  public Link getLink(String relation) {
    return null;
  }

  @Override
  public Link.Builder getLinkBuilder(String relation) {
    throw new UnsupportedOperationException("Link headers are not supported");
  }

  @Override
  public MultivaluedMap<String, Object> getMetadata() {
    return headers;
  }

  @Override
  public MultivaluedMap<String, String> getStringHeaders() {
    MultivaluedMap<String, String> stringHeaders = new MultivaluedHashMap<>();
    for (Map.Entry<String, List<Object>> entry : headers.entrySet()) {
      for (Object value : entry.getValue()) {
        stringHeaders.add(entry.getKey(), value == null ? null : String.valueOf(value));
      }
    }
    return stringHeaders;
  }

  @Override
  public String getHeaderString(String name) {
    List<Object> values = headers.get(name);
    if (values == null || values.isEmpty()) {
      return null;
    }
    Map<Integer, String> ordered = new LinkedHashMap<>();
    for (int i = 0; i < values.size(); i++) {
      ordered.put(i, values.get(i) == null ? "" : String.valueOf(values.get(i)));
    }
    return String.join(",", ordered.values());
  }

  private static StatusType toStatusType(int status) {
    Response.Status known = Response.Status.fromStatusCode(status);
    if (known != null) {
      return known;
    }
    return new StatusType() {
      @Override
      public int getStatusCode() {
        return status;
      }

      @Override
      public Status.Family getFamily() {
        return Status.Family.familyOf(status);
      }

      @Override
      public String getReasonPhrase() {
        return "";
      }
    };
  }
}
