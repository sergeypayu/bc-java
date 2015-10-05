package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <pre>
 * OriginatorIdentifierOrKey ::= CHOICE {
 *     issuerAndSerialNumber IssuerAndSerialNumber,
 *     subjectKeyIdentifier [0] SubjectKeyIdentifier,
 *     originatorKey [1] OriginatorPublicKey 
 * }
 *
 * SubjectKeyIdentifier ::= OCTET STRING
 * </pre>
 */
public class OriginatorIdentifierOrKey
    extends ASN1Object
    implements ASN1Choice
{
	private IssuerAndSerialNumber issuerSerial;
	private SubjectKeyIdentifier subjectKeyId;
	private OriginatorPublicKey originatorPublicKey;

    /**
     * Return an OriginatorIdentifierOrKey object from a tagged object.
     *
     * @param o the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static OriginatorIdentifierOrKey getInstance(
        ASN1TaggedObject    o,
        boolean             explicit)
    {
        if (!explicit)
        {
            throw new IllegalArgumentException(
                    "Can't implicitly tag OriginatorIdentifierOrKey");
        }

        return getInstance(o.getObject());
    }
    
    /**
     * Return an OriginatorIdentifierOrKey object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link OriginatorIdentifierOrKey} object
     * <li> {@link IssuerAndSerialNumber} object
     * <li> {@link SubjectKeyIdentifier} object
     * <li> {@link OriginatorPublicKey} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with IssuerAndSerialNumber structure inside
     * <li> {@link org.bouncycastle.asn1.ASN1TaggedObject#getInstance(java.lang.Object) ASN1TaggedObject} with tag value 0: a SubjectKeyIdentifier data structure, 1: OriginatorPublicKey
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static OriginatorIdentifierOrKey getInstance(
        Object obj)
    {
        if (obj == null || obj instanceof OriginatorIdentifierOrKey)
        {
            return (OriginatorIdentifierOrKey)obj;
        }

        if (obj instanceof IssuerAndSerialNumber)
        {
            return new OriginatorIdentifierOrKey((IssuerAndSerialNumber)obj);
        }

        if (obj instanceof SubjectKeyIdentifier)
        {
            return new OriginatorIdentifierOrKey((SubjectKeyIdentifier)obj);
        }

        if (obj instanceof OriginatorPublicKey)
        {
            return new OriginatorIdentifierOrKey((OriginatorPublicKey)obj);
        }

        if (obj instanceof ASN1Sequence)
        {
        	return new OriginatorIdentifierOrKey(IssuerAndSerialNumber.getInstance(obj));
        }
        
        if (obj instanceof ASN1TaggedObject && ((ASN1TaggedObject)obj).getTagNo() == 0)
        {
            return new OriginatorIdentifierOrKey(SubjectKeyIdentifier.getInstance((ASN1TaggedObject)obj, false));
        }
        
        if (obj instanceof ASN1TaggedObject && ((ASN1TaggedObject)obj).getTagNo() == 1)
        {
            return new OriginatorIdentifierOrKey(OriginatorPublicKey.getInstance((ASN1TaggedObject)obj, false));
        }
        
        throw new IllegalArgumentException("Invalid OriginatorIdentifierOrKey: " + obj.getClass().getName());
    }

    public OriginatorIdentifierOrKey(
            IssuerAndSerialNumber issuerSerial)
    {
        this.issuerSerial = issuerSerial;
        this.subjectKeyId = null;
        this.originatorPublicKey = null;
    }

    public OriginatorIdentifierOrKey(
        SubjectKeyIdentifier subjectKeyId)
    {
    	this.issuerSerial = null;
        this.subjectKeyId = subjectKeyId;
        this.originatorPublicKey = null;
    }

    public OriginatorIdentifierOrKey(
        OriginatorPublicKey originatorPublicKey)
    {
    	this.issuerSerial = null;
        this.subjectKeyId = null;
        this.originatorPublicKey = originatorPublicKey;
    }
        
    public IssuerAndSerialNumber getIssuerAndSerialNumber()
    {
        return issuerSerial;
    }

    public SubjectKeyIdentifier getSubjectKeyIdentifier()
    {
        return subjectKeyId;
    }

    public OriginatorPublicKey getOriginatorKey()
    {
        return originatorPublicKey;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
    	if (issuerSerial != null)
        {
            return issuerSerial.toASN1Primitive();
        } 
    	else if (subjectKeyId != null) 
    	{
    		return new DERTaggedObject(false, 0, subjectKeyId);
        } 
    	else 
    	{
    		return new DERTaggedObject(false, 1, originatorPublicKey);
        }
    }
}
