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

    public DSTU4145Params(ASN1ObjectIdentifier namedCurve, ASN1OctetString dke)
    {
        this.namedCurve = namedCurve;
        this.dke = dke;
        this.ecbinary = null;
    }

    public DSTU4145Params(DSTU4145ECBinary ecbinary, ASN1OctetString dke)
    {
        this.ecbinary = ecbinary;
        this.dke = dke;
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
            if (seq.size() > 1) {
            	dke = ASN1OctetString.getInstance(seq.getObjectAt(1));
            }
            
            DSTU4145Params params;
            
            if (seq.getObjectAt(0) instanceof ASN1ObjectIdentifier)
            {
            	params = new DSTU4145Params(ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0)), dke);
            }
            else
            {
            	params = new DSTU4145Params(DSTU4145ECBinary.getInstance(seq.getObjectAt(0)), dke);
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
     * 		dke OCTET STRING OPTIONAL
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

        return new DERSequence(v);
    }
}
