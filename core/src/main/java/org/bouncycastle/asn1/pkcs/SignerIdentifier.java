package org.bouncycastle.asn1.pkcs;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

public class SignerIdentifier 
	extends ASN1Object
	implements ASN1Choice
{
    private IssuerAndSerialNumber   issuerAndSerialNumber;
    private SubjectKeyIdentifier    subjectKeyIdentifier;

    public static SignerIdentifier getInstance(Object o)
    {
        if (o instanceof SignerIdentifier)
        {
            return (SignerIdentifier)o;
        }
        else if (o instanceof ASN1TaggedObject)
        {
        	return new SignerIdentifier(SubjectKeyIdentifier.getInstance(((ASN1TaggedObject)o).getObject()));
        }
        else if (o instanceof ASN1Sequence)
        {
            return new SignerIdentifier(IssuerAndSerialNumber.getInstance((ASN1Sequence)o));
        }

        throw new IllegalArgumentException("unknown object in factory: " + o.getClass().getName());
    }

    public SignerIdentifier(SubjectKeyIdentifier subjectKeyIdentifier)
    {
        this.subjectKeyIdentifier = subjectKeyIdentifier;
        this.issuerAndSerialNumber = null;
    }
    
    public SignerIdentifier(IssuerAndSerialNumber issuerAndSerialNumber)
    {
        this.issuerAndSerialNumber = issuerAndSerialNumber;
        this.subjectKeyIdentifier = null;
    }

    public IssuerAndSerialNumber getIssuerAndSerialNumber()
    {
        return issuerAndSerialNumber;
    }

    public SubjectKeyIdentifier getSubjectKeyIdentifier()
    {
        return subjectKeyIdentifier;
    }

    /**
     * <pre>
     *    SignerIdentifier ::= CHOICE {
     *        issuerAndSerialNumber        IssuerAndSerialNumber,
     *        subjectKeyIdentifier     [0] SubjectKeyIdentifier }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
    	if (issuerAndSerialNumber != null) {
    		return issuerAndSerialNumber.toASN1Primitive();
    	}
    	
    	return new DERTaggedObject(false, 0, subjectKeyIdentifier);
    }
}
