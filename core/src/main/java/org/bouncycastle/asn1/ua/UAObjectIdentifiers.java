package org.bouncycastle.asn1.ua;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Ukrainian object identifiers
 * <p>
 * {iso(1) member-body(2) Ukraine(804) root(2) security(1) cryptography(1) pki(1)}
 * <p>
 * { ...  pki-alg(1) pki-alg-sym(3) Dstu4145WithGost34311(1) PB(1)}
 * <p>
 * DSTU4145 in polynomial basis has 2 oids, one for little-endian representation and one for big-endian
 */
public interface UAObjectIdentifiers
{
    /** Base OID: 1.2.804.2.1.1.1 */
    static final ASN1ObjectIdentifier UaOid = new ASN1ObjectIdentifier("1.2.804.2.1.1.1");

    /** DSTU4145 Little Endian presentation.  OID: 1.2.804.2.1.1.1.1.3.1.1 */
    static final ASN1ObjectIdentifier dstu4145le = UaOid.branch("1.3.1.1");
    /** DSTU4145 Big Endian presentation.  OID: 1.2.804.2.1.1.1.1.3.1.1.1 */
    static final ASN1ObjectIdentifier dstu4145be = UaOid.branch("1.3.1.1.1.1");
    
    /** Prikaz 1236 Named Curves PB.  OID: 1.2.804.2.1.1.1.1.3.1.1.2.X */
    static final ASN1ObjectIdentifier p1236namedСurvesPB = UaOid.branch("1.3.1.1.2");
    static final ASN1ObjectIdentifier m163PB = p1236namedСurvesPB.branch("0");
    static final ASN1ObjectIdentifier m167PB = p1236namedСurvesPB.branch("1");
    static final ASN1ObjectIdentifier m173PB = p1236namedСurvesPB.branch("2");
    static final ASN1ObjectIdentifier m179PB = p1236namedСurvesPB.branch("3");
    static final ASN1ObjectIdentifier m191PB = p1236namedСurvesPB.branch("4");
    static final ASN1ObjectIdentifier m233PB = p1236namedСurvesPB.branch("5");
    static final ASN1ObjectIdentifier m257PB = p1236namedСurvesPB.branch("6");
    static final ASN1ObjectIdentifier m307PB = p1236namedСurvesPB.branch("7");
    static final ASN1ObjectIdentifier m367PB = p1236namedСurvesPB.branch("8");
    static final ASN1ObjectIdentifier m431PB = p1236namedСurvesPB.branch("9");
    
    /** Prikaz 1236 Named Curves ONB.  OID: 1.2.804.2.1.1.1.1.3.1.2.2.X */
    static final ASN1ObjectIdentifier p1236namedСurvesONB = UaOid.branch("1.3.1.2.2");
    static final ASN1ObjectIdentifier m173ONB = p1236namedСurvesONB.branch("0");
    static final ASN1ObjectIdentifier m179ONB = p1236namedСurvesONB.branch("1");
    static final ASN1ObjectIdentifier m191ONB = p1236namedСurvesONB.branch("2");
    static final ASN1ObjectIdentifier m233ONB = p1236namedСurvesONB.branch("3");
    static final ASN1ObjectIdentifier m431ONB = p1236namedСurvesONB.branch("4");

    /** GOST28147 Encryption OFB Mode 1.2.804.2.1.1.1.1.1.1.2 */
    static final ASN1ObjectIdentifier gost28147ofb = UaOid.branch("1.1.1.2");
    /** GOST28147 Encryption CFB Mode 1.2.804.2.1.1.1.1.1.1.3 */
    static final ASN1ObjectIdentifier gost28147cfb = UaOid.branch("1.1.1.3");
    /** GOST28147 Wrap 1.2.804.2.1.1.1.1.1.1.5 */
    static final ASN1ObjectIdentifier gost28147wrap = UaOid.branch("1.1.1.5");

    /** DH Key Agreement w Cofactor 1.2.804.2.1.1.1.1.3.4 */
    static final ASN1ObjectIdentifier dhSinglePassCofactorDHGost34311kdf = UaOid.branch("1.3.4");
	/** DH Key Agreement w/o Cofactor 1.2.804.2.1.1.1.1.3.5 */
    static final ASN1ObjectIdentifier dhSinglePassStdDHGost34311kdf = UaOid.branch("1.1.3.5");
	
    /** Gost34311 1.2.804.2.1.1.1.1.2.1 */
    static final ASN1ObjectIdentifier gost34311 = UaOid.branch("1.2.1");
    /** HMac with Gost34311 1.2.804.2.1.1.1.1.1.2 */
    static final ASN1ObjectIdentifier hmacGost34311 = UaOid.branch("1.1.2");
    
    /** Subject Directory Attribute: DRFO 1.2.804.2.1.1.1.11.1.4.1.1 */
    static final ASN1ObjectIdentifier drfo = UaOid.branch("11.1.4.1.1");
    /** Subject Directory Attribute: EDRPOU 1.2.804.2.1.1.1.11.1.4.2.1  */
    static final ASN1ObjectIdentifier edrpou = UaOid.branch("11.1.4.2.1");
    
    /** Extended Key Usage: stamp 1.2.804.2.1.1.1.3.9 */
	static final ASN1ObjectIdentifier stampUsage = UaOid.branch("3.9");
	
	/** Qualified Mark 1.2.804.2.1.1.1.2.2 */
	static final ASN1ObjectIdentifier certQualified = UaOid.branch("2.2");
}
