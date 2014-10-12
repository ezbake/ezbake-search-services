/*   Copyright (C) 2013-2014 Computer Sciences Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */

/**
 * Autogenerated by Thrift Compiler (0.9.1)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
package ezbake.services.search;

import org.apache.thrift.scheme.IScheme;
import org.apache.thrift.scheme.SchemeFactory;
import org.apache.thrift.scheme.StandardScheme;

import org.apache.thrift.scheme.TupleScheme;
import org.apache.thrift.protocol.TTupleProtocol;
import org.apache.thrift.protocol.TProtocolException;
import org.apache.thrift.EncodingUtils;
import org.apache.thrift.TException;
import org.apache.thrift.async.AsyncMethodCallback;
import org.apache.thrift.server.AbstractNonblockingServer.*;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.EnumMap;
import java.util.Set;
import java.util.HashSet;
import java.util.EnumSet;
import java.util.Collections;
import java.util.BitSet;
import java.nio.ByteBuffer;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FacetValue implements org.apache.thrift.TBase<FacetValue, FacetValue._Fields>, java.io.Serializable, Cloneable, Comparable<FacetValue> {
  private static final org.apache.thrift.protocol.TStruct STRUCT_DESC = new org.apache.thrift.protocol.TStruct("FacetValue");

  private static final org.apache.thrift.protocol.TField LABEL_FIELD_DESC = new org.apache.thrift.protocol.TField("label", org.apache.thrift.protocol.TType.STRING, (short)1);
  private static final org.apache.thrift.protocol.TField VALUE_FIELD_DESC = new org.apache.thrift.protocol.TField("value", org.apache.thrift.protocol.TType.STRUCT, (short)2);
  private static final org.apache.thrift.protocol.TField COUNT_FIELD_DESC = new org.apache.thrift.protocol.TField("count", org.apache.thrift.protocol.TType.STRING, (short)3);

  private static final Map<Class<? extends IScheme>, SchemeFactory> schemes = new HashMap<Class<? extends IScheme>, SchemeFactory>();
  static {
    schemes.put(StandardScheme.class, new FacetValueStandardSchemeFactory());
    schemes.put(TupleScheme.class, new FacetValueTupleSchemeFactory());
  }

  public String label; // optional
  public RawValue value; // optional
  public String count; // optional

  /** The set of fields this struct contains, along with convenience methods for finding and manipulating them. */
  public enum _Fields implements org.apache.thrift.TFieldIdEnum {
    LABEL((short)1, "label"),
    VALUE((short)2, "value"),
    COUNT((short)3, "count");

    private static final Map<String, _Fields> byName = new HashMap<String, _Fields>();

    static {
      for (_Fields field : EnumSet.allOf(_Fields.class)) {
        byName.put(field.getFieldName(), field);
      }
    }

    /**
     * Find the _Fields constant that matches fieldId, or null if its not found.
     */
    public static _Fields findByThriftId(int fieldId) {
      switch(fieldId) {
        case 1: // LABEL
          return LABEL;
        case 2: // VALUE
          return VALUE;
        case 3: // COUNT
          return COUNT;
        default:
          return null;
      }
    }

    /**
     * Find the _Fields constant that matches fieldId, throwing an exception
     * if it is not found.
     */
    public static _Fields findByThriftIdOrThrow(int fieldId) {
      _Fields fields = findByThriftId(fieldId);
      if (fields == null) throw new IllegalArgumentException("Field " + fieldId + " doesn't exist!");
      return fields;
    }

    /**
     * Find the _Fields constant that matches name, or null if its not found.
     */
    public static _Fields findByName(String name) {
      return byName.get(name);
    }

    private final short _thriftId;
    private final String _fieldName;

    _Fields(short thriftId, String fieldName) {
      _thriftId = thriftId;
      _fieldName = fieldName;
    }

    public short getThriftFieldId() {
      return _thriftId;
    }

    public String getFieldName() {
      return _fieldName;
    }
  }

  // isset id assignments
  private _Fields optionals[] = {_Fields.LABEL,_Fields.VALUE,_Fields.COUNT};
  public static final Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> metaDataMap;
  static {
    Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> tmpMap = new EnumMap<_Fields, org.apache.thrift.meta_data.FieldMetaData>(_Fields.class);
    tmpMap.put(_Fields.LABEL, new org.apache.thrift.meta_data.FieldMetaData("label", org.apache.thrift.TFieldRequirementType.OPTIONAL, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.STRING)));
    tmpMap.put(_Fields.VALUE, new org.apache.thrift.meta_data.FieldMetaData("value", org.apache.thrift.TFieldRequirementType.OPTIONAL, 
        new org.apache.thrift.meta_data.StructMetaData(org.apache.thrift.protocol.TType.STRUCT, RawValue.class)));
    tmpMap.put(_Fields.COUNT, new org.apache.thrift.meta_data.FieldMetaData("count", org.apache.thrift.TFieldRequirementType.OPTIONAL, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.STRING)));
    metaDataMap = Collections.unmodifiableMap(tmpMap);
    org.apache.thrift.meta_data.FieldMetaData.addStructMetaDataMap(FacetValue.class, metaDataMap);
  }

  public FacetValue() {
  }

  /**
   * Performs a deep copy on <i>other</i>.
   */
  public FacetValue(FacetValue other) {
    if (other.isSetLabel()) {
      this.label = other.label;
    }
    if (other.isSetValue()) {
      this.value = new RawValue(other.value);
    }
    if (other.isSetCount()) {
      this.count = other.count;
    }
  }

  public FacetValue deepCopy() {
    return new FacetValue(this);
  }

  @Override
  public void clear() {
    this.label = null;
    this.value = null;
    this.count = null;
  }

  public String getLabel() {
    return this.label;
  }

  public FacetValue setLabel(String label) {
    this.label = label;
    return this;
  }

  public void unsetLabel() {
    this.label = null;
  }

  /** Returns true if field label is set (has been assigned a value) and false otherwise */
  public boolean isSetLabel() {
    return this.label != null;
  }

  public void setLabelIsSet(boolean value) {
    if (!value) {
      this.label = null;
    }
  }

  public RawValue getValue() {
    return this.value;
  }

  public FacetValue setValue(RawValue value) {
    this.value = value;
    return this;
  }

  public void unsetValue() {
    this.value = null;
  }

  /** Returns true if field value is set (has been assigned a value) and false otherwise */
  public boolean isSetValue() {
    return this.value != null;
  }

  public void setValueIsSet(boolean value) {
    if (!value) {
      this.value = null;
    }
  }

  public String getCount() {
    return this.count;
  }

  public FacetValue setCount(String count) {
    this.count = count;
    return this;
  }

  public void unsetCount() {
    this.count = null;
  }

  /** Returns true if field count is set (has been assigned a value) and false otherwise */
  public boolean isSetCount() {
    return this.count != null;
  }

  public void setCountIsSet(boolean value) {
    if (!value) {
      this.count = null;
    }
  }

  public void setFieldValue(_Fields field, Object value) {
    switch (field) {
    case LABEL:
      if (value == null) {
        unsetLabel();
      } else {
        setLabel((String)value);
      }
      break;

    case VALUE:
      if (value == null) {
        unsetValue();
      } else {
        setValue((RawValue)value);
      }
      break;

    case COUNT:
      if (value == null) {
        unsetCount();
      } else {
        setCount((String)value);
      }
      break;

    }
  }

  public Object getFieldValue(_Fields field) {
    switch (field) {
    case LABEL:
      return getLabel();

    case VALUE:
      return getValue();

    case COUNT:
      return getCount();

    }
    throw new IllegalStateException();
  }

  /** Returns true if field corresponding to fieldID is set (has been assigned a value) and false otherwise */
  public boolean isSet(_Fields field) {
    if (field == null) {
      throw new IllegalArgumentException();
    }

    switch (field) {
    case LABEL:
      return isSetLabel();
    case VALUE:
      return isSetValue();
    case COUNT:
      return isSetCount();
    }
    throw new IllegalStateException();
  }

  @Override
  public boolean equals(Object that) {
    if (that == null)
      return false;
    if (that instanceof FacetValue)
      return this.equals((FacetValue)that);
    return false;
  }

  public boolean equals(FacetValue that) {
    if (that == null)
      return false;

    boolean this_present_label = true && this.isSetLabel();
    boolean that_present_label = true && that.isSetLabel();
    if (this_present_label || that_present_label) {
      if (!(this_present_label && that_present_label))
        return false;
      if (!this.label.equals(that.label))
        return false;
    }

    boolean this_present_value = true && this.isSetValue();
    boolean that_present_value = true && that.isSetValue();
    if (this_present_value || that_present_value) {
      if (!(this_present_value && that_present_value))
        return false;
      if (!this.value.equals(that.value))
        return false;
    }

    boolean this_present_count = true && this.isSetCount();
    boolean that_present_count = true && that.isSetCount();
    if (this_present_count || that_present_count) {
      if (!(this_present_count && that_present_count))
        return false;
      if (!this.count.equals(that.count))
        return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    return 0;
  }

  @Override
  public int compareTo(FacetValue other) {
    if (!getClass().equals(other.getClass())) {
      return getClass().getName().compareTo(other.getClass().getName());
    }

    int lastComparison = 0;

    lastComparison = Boolean.valueOf(isSetLabel()).compareTo(other.isSetLabel());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetLabel()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.label, other.label);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = Boolean.valueOf(isSetValue()).compareTo(other.isSetValue());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetValue()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.value, other.value);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = Boolean.valueOf(isSetCount()).compareTo(other.isSetCount());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetCount()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.count, other.count);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    return 0;
  }

  public _Fields fieldForId(int fieldId) {
    return _Fields.findByThriftId(fieldId);
  }

  public void read(org.apache.thrift.protocol.TProtocol iprot) throws org.apache.thrift.TException {
    schemes.get(iprot.getScheme()).getScheme().read(iprot, this);
  }

  public void write(org.apache.thrift.protocol.TProtocol oprot) throws org.apache.thrift.TException {
    schemes.get(oprot.getScheme()).getScheme().write(oprot, this);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder("FacetValue(");
    boolean first = true;

    if (isSetLabel()) {
      sb.append("label:");
      if (this.label == null) {
        sb.append("null");
      } else {
        sb.append(this.label);
      }
      first = false;
    }
    if (isSetValue()) {
      if (!first) sb.append(", ");
      sb.append("value:");
      if (this.value == null) {
        sb.append("null");
      } else {
        sb.append(this.value);
      }
      first = false;
    }
    if (isSetCount()) {
      if (!first) sb.append(", ");
      sb.append("count:");
      if (this.count == null) {
        sb.append("null");
      } else {
        sb.append(this.count);
      }
      first = false;
    }
    sb.append(")");
    return sb.toString();
  }

  public void validate() throws org.apache.thrift.TException {
    // check for required fields
    // check for sub-struct validity
  }

  private void writeObject(java.io.ObjectOutputStream out) throws java.io.IOException {
    try {
      write(new org.apache.thrift.protocol.TCompactProtocol(new org.apache.thrift.transport.TIOStreamTransport(out)));
    } catch (org.apache.thrift.TException te) {
      throw new java.io.IOException(te);
    }
  }

  private void readObject(java.io.ObjectInputStream in) throws java.io.IOException, ClassNotFoundException {
    try {
      read(new org.apache.thrift.protocol.TCompactProtocol(new org.apache.thrift.transport.TIOStreamTransport(in)));
    } catch (org.apache.thrift.TException te) {
      throw new java.io.IOException(te);
    }
  }

  private static class FacetValueStandardSchemeFactory implements SchemeFactory {
    public FacetValueStandardScheme getScheme() {
      return new FacetValueStandardScheme();
    }
  }

  private static class FacetValueStandardScheme extends StandardScheme<FacetValue> {

    public void read(org.apache.thrift.protocol.TProtocol iprot, FacetValue struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TField schemeField;
      iprot.readStructBegin();
      while (true)
      {
        schemeField = iprot.readFieldBegin();
        if (schemeField.type == org.apache.thrift.protocol.TType.STOP) { 
          break;
        }
        switch (schemeField.id) {
          case 1: // LABEL
            if (schemeField.type == org.apache.thrift.protocol.TType.STRING) {
              struct.label = iprot.readString();
              struct.setLabelIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 2: // VALUE
            if (schemeField.type == org.apache.thrift.protocol.TType.STRUCT) {
              struct.value = new RawValue();
              struct.value.read(iprot);
              struct.setValueIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 3: // COUNT
            if (schemeField.type == org.apache.thrift.protocol.TType.STRING) {
              struct.count = iprot.readString();
              struct.setCountIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          default:
            org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
        }
        iprot.readFieldEnd();
      }
      iprot.readStructEnd();

      // check for required fields of primitive type, which can't be checked in the validate method
      struct.validate();
    }

    public void write(org.apache.thrift.protocol.TProtocol oprot, FacetValue struct) throws org.apache.thrift.TException {
      struct.validate();

      oprot.writeStructBegin(STRUCT_DESC);
      if (struct.label != null) {
        if (struct.isSetLabel()) {
          oprot.writeFieldBegin(LABEL_FIELD_DESC);
          oprot.writeString(struct.label);
          oprot.writeFieldEnd();
        }
      }
      if (struct.value != null) {
        if (struct.isSetValue()) {
          oprot.writeFieldBegin(VALUE_FIELD_DESC);
          struct.value.write(oprot);
          oprot.writeFieldEnd();
        }
      }
      if (struct.count != null) {
        if (struct.isSetCount()) {
          oprot.writeFieldBegin(COUNT_FIELD_DESC);
          oprot.writeString(struct.count);
          oprot.writeFieldEnd();
        }
      }
      oprot.writeFieldStop();
      oprot.writeStructEnd();
    }

  }

  private static class FacetValueTupleSchemeFactory implements SchemeFactory {
    public FacetValueTupleScheme getScheme() {
      return new FacetValueTupleScheme();
    }
  }

  private static class FacetValueTupleScheme extends TupleScheme<FacetValue> {

    @Override
    public void write(org.apache.thrift.protocol.TProtocol prot, FacetValue struct) throws org.apache.thrift.TException {
      TTupleProtocol oprot = (TTupleProtocol) prot;
      BitSet optionals = new BitSet();
      if (struct.isSetLabel()) {
        optionals.set(0);
      }
      if (struct.isSetValue()) {
        optionals.set(1);
      }
      if (struct.isSetCount()) {
        optionals.set(2);
      }
      oprot.writeBitSet(optionals, 3);
      if (struct.isSetLabel()) {
        oprot.writeString(struct.label);
      }
      if (struct.isSetValue()) {
        struct.value.write(oprot);
      }
      if (struct.isSetCount()) {
        oprot.writeString(struct.count);
      }
    }

    @Override
    public void read(org.apache.thrift.protocol.TProtocol prot, FacetValue struct) throws org.apache.thrift.TException {
      TTupleProtocol iprot = (TTupleProtocol) prot;
      BitSet incoming = iprot.readBitSet(3);
      if (incoming.get(0)) {
        struct.label = iprot.readString();
        struct.setLabelIsSet(true);
      }
      if (incoming.get(1)) {
        struct.value = new RawValue();
        struct.value.read(iprot);
        struct.setValueIsSet(true);
      }
      if (incoming.get(2)) {
        struct.count = iprot.readString();
        struct.setCountIsSet(true);
      }
    }
  }

}
