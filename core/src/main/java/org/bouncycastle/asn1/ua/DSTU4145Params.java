package org.bouncycastle.asn1.ua;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class DSTU4145Params
    extends ASN1Object
{
    private ASN1ObjectIdentifier namedCurve;
    private DSTU4145ECBinary ecbinary;
    private ASN1OctetString dke;
    private ASN1OctetString dke2;

    public DSTU4145Params(ASN1ObjectIdentifier namedCurve)
    {
        this(namedCurve, null, null);
    }

    public DSTU4145Params(ASN1ObjectIdentifier namedCurve, ASN1OctetString dke)
    {
        this(namedCurve, dke, null);
    }

    public DSTU4145Params(ASN1ObjectIdentifier namedCurve, ASN1OctetString dke, ASN1OctetString dke2)
    {
        this.namedCurve = namedCurve;
        this.dke = dke;
        this.dke2 = dke2;
        this.ecbinary = null;
    }

    public DSTU4145Params(DSTU4145ECBinary ecbinary)
    {
        this(ecbinary, null, null);
    }

    public DSTU4145Params(DSTU4145ECBinary ecbinary, ASN1OctetString dke)
    {
        this(ecbinary, dke, null);
    }

    public DSTU4145Params(DSTU4145ECBinary ecbinary, ASN1OctetString dke, ASN1OctetString dke2)
    {
        this.ecbinary = ecbinary;
        this.dke = dke;
        this.dke2 = dke2;
        this.namedCurve = null;
    }

    public boolean isNamedCurve()
    {
        return namedCurve != null;
    }

    public DSTU4145ECBinary getECBinary()
    {
        return ecbinary;
    }

    public byte[] getDKE()
    {
        return dke == null ? null : dke.getOctets();
    }

    public byte[] getDKE2()
    {
        return dke2 == null ? null : dke2.getOctets();
    }

    public ASN1ObjectIdentifier getNamedCurve()
    {
        return namedCurve;
    }

    public static DSTU4145Params getInstance(Object obj)
    {
        if (obj instanceof DSTU4145Params)
        {
            return (DSTU4145Params)obj;
        }

        if (obj != null)
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(obj);
            
            ASN1OctetString dke = null;
            ASN1OctetString dke2 = null;
            if (seq.size() > 1) {
            	dke = ASN1OctetString.getInstance(seq.getObjectAt(1));
            }
            if (seq.size() > 2) {
                dke2 = ASN1OctetString.getInstance(seq.getObjectAt(2));
            }
            
            DSTU4145Params params;
            
            if (seq.getObjectAt(0) instanceof ASN1ObjectIdentifier)
            {
            	params = new DSTU4145Params(ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0)), dke, dke2);
            }
            else
            {
            	params = new DSTU4145Params(DSTU4145ECBinary.getInstance(seq.getObjectAt(0)), dke, dke2);
            }

            return params;
        }

        throw new IllegalArgumentException("object parse error");
    }

    /*
     * 
     * DSTU4145Params::= SEQUENCE {
     * 		CHOICE {
     * 			ecbinary ECBinary,
     * 			namedCurve OBJECT IDENTIFIER
     * 		},
     * 		dke  OCTET STRING OPTIONAL
     * 		dke2 OCTET STRING OPTIONAL
     * 	}
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (namedCurve != null)
        {
            v.add(namedCurve);
        }
        else
        {
            v.add(ecbinary);
        }

        if (dke != null)
        {
            v.add(dke);
        }

        if (dke2 != null)
        {
            v.add(dke2);
        }

        return new DERSequence(v);
    }
}
