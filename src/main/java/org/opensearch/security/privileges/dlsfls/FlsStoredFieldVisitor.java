package org.opensearch.security.privileges.dlsfls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Set;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.index.FieldInfo;
import org.apache.lucene.index.StoredFieldVisitor;

import org.opensearch.OpenSearchException;

/**
 * Applies FLS and field masking while reading documents
 *
 * TODO
 *
 * https://github.com/opensearch-project/security/pull/4336
 * https://github.com/opensearch-project/security/pull/2375
 * https://github.com/opensearch-project/security/pull/3069
 */
public class FlsStoredFieldVisitor extends StoredFieldVisitor {
    private static final Logger log = LogManager.getLogger(FlsStoredFieldVisitor.class);

    private static final JsonFactory JSON_FACTORY = new JsonFactory();

    private final StoredFieldVisitor delegate;
    private final FieldPrivileges.FlsRule flsRule;
    private final FieldMasking.FieldMaskingRule fieldMaskingRule;
    private final Set<String> metaFields;

    public FlsStoredFieldVisitor(
        StoredFieldVisitor delegate,
        FieldPrivileges.FlsRule flsRule,
        FieldMasking.FieldMaskingRule fieldMaskingRule,
        Set<String> metaFields
    ) {
        super();
        this.delegate = delegate;
        this.flsRule = flsRule;
        this.fieldMaskingRule = fieldMaskingRule;
        this.metaFields = metaFields;

        if (log.isDebugEnabled()) {
            log.debug("Created FlsStoredFieldVisitor for {}; {}", flsRule, fieldMaskingRule);
        }
    }

    @Override
    public void binaryField(FieldInfo fieldInfo, byte[] value) throws IOException {

        if (fieldInfo.name.equals("_source")) {
            try {
                // TODO
                // if (delegate instanceof MaskedFieldsConsumer) {
                // ((MaskedFieldsConsumer) delegate).binaryMaskedField(fieldInfo,
                // DocumentFilter.filter(Format.JSON, value, flsRule, fieldMaskingRule),
                // (f) -> fieldMaskingRule != null && fieldMaskingRule.get(f) != null);
                // } else {
                delegate.binaryField(fieldInfo, DocumentFilter.filter(JSON_FACTORY, value, flsRule, fieldMaskingRule, metaFields));
                // }

            } catch (IOException e) {
                throw new OpenSearchException("Cannot filter source of document", e);
            }
        } else {
            delegate.binaryField(fieldInfo, value);
        }
    }

    @Override
    public Status needsField(FieldInfo fieldInfo) throws IOException {
        return metaFields.contains(fieldInfo.name) || flsRule.isAllowed(fieldInfo.name) ? delegate.needsField(fieldInfo) : Status.NO;
    }

    @Override
    public int hashCode() {
        return delegate.hashCode();
    }

    @Override
    public void intField(final FieldInfo fieldInfo, final int value) throws IOException {
        delegate.intField(fieldInfo, value);
    }

    @Override
    public void longField(final FieldInfo fieldInfo, final long value) throws IOException {
        delegate.longField(fieldInfo, value);
    }

    @Override
    public void floatField(final FieldInfo fieldInfo, final float value) throws IOException {
        delegate.floatField(fieldInfo, value);
    }

    @Override
    public void doubleField(final FieldInfo fieldInfo, final double value) throws IOException {
        delegate.doubleField(fieldInfo, value);
    }

    @Override
    public boolean equals(final Object obj) {
        return delegate.equals(obj);
    }

    @Override
    public String toString() {
        return delegate.toString();
    }

    public StoredFieldVisitor delegate() {
        return this.delegate;
    }

    static class DocumentFilter {
        public static byte[] filter(
            JsonFactory jsonFactory,
            byte[] bytes,
            FieldPrivileges.FlsRule flsRule,
            FieldMasking.FieldMaskingRule fieldMaskingRule,
            Set<String> metaFields
        ) throws IOException {
            try (InputStream in = new ByteArrayInputStream(bytes); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                filter(jsonFactory, in, out, flsRule, fieldMaskingRule, metaFields);
                return out.toByteArray();
            }
        }

        public static void filter(
            JsonFactory jsonFactory,
            InputStream in,
            OutputStream out,
            FieldPrivileges.FlsRule flsRule,
            FieldMasking.FieldMaskingRule fieldMaskingRule,
            Set<String> metaFields
        ) throws IOException {
            try (JsonParser parser = jsonFactory.createParser(in); JsonGenerator generator = jsonFactory.createGenerator(out)) {
                new DocumentFilter(parser, generator, flsRule, fieldMaskingRule, metaFields).copy();
            }
        }

        private final JsonParser parser;
        private final JsonGenerator generator;
        private final FieldPrivileges.FlsRule flsRule;
        private final FieldMasking.FieldMaskingRule fieldMaskingRule;
        private final Set<String> metaFields;
        private String currentName;
        private String fullCurrentName;
        private String fullParentName;
        private Deque<String> nameStack = new ArrayDeque<>();

        DocumentFilter(
            JsonParser parser,
            JsonGenerator generator,
            FieldPrivileges.FlsRule flsRule,
            FieldMasking.FieldMaskingRule fieldMaskingRule,
            Set<String> metaFields
        ) {
            this.parser = parser;
            this.generator = generator;
            this.flsRule = flsRule;
            this.fieldMaskingRule = fieldMaskingRule;
            this.metaFields = metaFields;
        }

        @SuppressWarnings("incomplete-switch")
        private void copy() throws IOException {
            boolean skipNext = false;

            for (JsonToken token = parser.currentToken() != null ? parser.currentToken() : parser.nextToken(); token != null; token = parser
                .nextToken()) {

                if (!skipNext) {
                    switch (token) {

                        case START_OBJECT:
                            generator.writeStartObject();
                            if (fullParentName != null) {
                                nameStack.add(fullParentName);
                            }
                            this.fullParentName = this.fullCurrentName;
                            break;

                        case START_ARRAY:
                            generator.writeStartArray();
                            break;

                        case END_OBJECT:
                            generator.writeEndObject();
                            if (nameStack.isEmpty()) {
                                fullParentName = null;
                            } else {
                                fullParentName = nameStack.removeLast();
                            }
                            break;

                        case END_ARRAY:
                            generator.writeEndArray();
                            break;

                        case FIELD_NAME:
                            this.currentName = parser.currentName();
                            this.fullCurrentName = this.fullParentName == null
                                ? this.currentName
                                : this.fullParentName + "." + this.currentName;

                            if (metaFields.contains(fullCurrentName) || flsRule.isAllowed(fullCurrentName)) {
                                generator.writeFieldName(parser.currentName());
                            } else {
                                skipNext = true;
                            }
                            break;

                        case VALUE_TRUE:
                            generator.writeBoolean(Boolean.TRUE);
                            break;

                        case VALUE_FALSE:
                            generator.writeBoolean(Boolean.FALSE);
                            break;

                        case VALUE_NULL:
                            generator.writeNull();
                            break;

                        case VALUE_NUMBER_FLOAT:
                            generator.writeNumber(parser.getFloatValue());
                            break;

                        case VALUE_NUMBER_INT:
                            generator.writeNumber(parser.getIntValue());
                            break;

                        case VALUE_STRING:
                            FieldMasking.FieldMaskingRule.Field field = fieldMaskingRule.get(this.fullCurrentName);

                            if (field != null) {
                                generator.writeString(field.apply(parser.getText()));
                            } else {
                                generator.writeString(parser.getText());
                            }

                            break;

                        case VALUE_EMBEDDED_OBJECT:
                            generator.writeEmbeddedObject(parser.getEmbeddedObject());
                            break;

                        default:
                            throw new IllegalStateException("Unexpected token: " + token);

                    }

                } else {
                    skipNext = false;
                    switch (token) {
                        case START_OBJECT:
                        case START_ARRAY:
                            parser.skipChildren();
                            break;
                    }
                }
            }
        }
    }
}
