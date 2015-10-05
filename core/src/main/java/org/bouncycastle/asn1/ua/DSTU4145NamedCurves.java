package org.bouncycastle.asn1.ua;

import java.math.BigInteger;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class DSTU4145NamedCurves
{
    static X9ECParametersHolder m163PB = new X9ECParametersHolder()
    {
    	protected X9ECParameters createParameters()
        {
			ECCurve m163PB = new ECCurve.F2m(163, 3, 6, 7, BigInteger.ONE, new BigInteger("5FF6108462A2DC8210AB403925E638A19C1455D21", 16));
			ECPoint P = m163PB.createPoint(new BigInteger("72D867F93A93AC27DF9FF01AFFE74885C8C540420", 16), 
										   new BigInteger("0224A9C3947852B97C5599D5F4AB81122ADC3FD9B", 16));
			BigInteger n = new BigInteger("400000000000000000002BEC12BE2262D39BCF14D", 16);
            BigInteger h = BigInteger.valueOf(2);

            return new X9ECParameters(m163PB, P, n, h, null);
        }
    };
			
    static X9ECParametersHolder m167PB = new X9ECParametersHolder()
    {
    	protected X9ECParameters createParameters()
        {
			ECCurve m167PB = new ECCurve.F2m(167, 6, 0, 0, BigInteger.ONE, new BigInteger("6EE3CEEB230811759F20518A0930F1A4315A827DAC", 16));
			ECPoint P = m167PB.createPoint(new BigInteger("7A1F6653786A68192803910A3D30B2A2018B21CD54", 16), 
										   new BigInteger("5F49EB26781C0EC6B8909156D98ED435E45FD59918", 16));
			BigInteger n = new BigInteger("3FFFFFFFFFFFFFFFFFFFFFB12EBCC7D7F29FF7701F", 16);
            BigInteger h = BigInteger.valueOf(2);

            return new X9ECParameters(m167PB, P, n, h, null);
        }
    };
		
    static X9ECParametersHolder m173PB = new X9ECParametersHolder()
    {
    	protected X9ECParameters createParameters()
        {
			ECCurve m173PB = new ECCurve.F2m(173, 1, 2, 10, BigInteger.ZERO, new BigInteger("108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9", 16));
			ECPoint P = m173PB.createPoint(new BigInteger("4D41A619BCC6EADF0448FA22FAD567A9181D37389CA", 16), 
										   new BigInteger("10B51CC12849B234C75E6DD2028BF7FF5C1CE0D991A1", 16));
			BigInteger n = new BigInteger("800000000000000000000189B4E67606E3825BB2831", 16);
            BigInteger h = BigInteger.valueOf(4);

            return new X9ECParameters(m173PB, P, n, h, null);
        }
    };
			
    static X9ECParametersHolder m179PB = new X9ECParametersHolder()
    {
    	protected X9ECParameters createParameters()
        {
			ECCurve m179PB = new ECCurve.F2m(179, 1, 2, 4, BigInteger.ONE, new BigInteger("4A6E0856526436F2F88DD07A341E32D04184572BEB710", 16));
			ECPoint P = m179PB.createPoint(new BigInteger("6BA06FE51464B2BD26DC57F48819BA9954667022C7D03", 16), 
										   new BigInteger("25FBC363582DCEC065080CA8287AAFF09788A66DC3A9E", 16));
			BigInteger n = new BigInteger("3FFFFFFFFFFFFFFFFFFFFFFB981960435FE5AB64236EF", 16);
            BigInteger h = BigInteger.valueOf(2);

            return new X9ECParameters(m179PB, P, n, h, null);
        }
    };
			
    static X9ECParametersHolder m191PB = new X9ECParametersHolder()
    {
    	protected X9ECParameters createParameters()
        {
			ECCurve m191PB = new ECCurve.F2m(191, 9, 0, 0, BigInteger.ONE, new BigInteger("7BC86E2102902EC4D5890E8B6B4981ff27E0482750FEFC03", 16));
			ECPoint P = m191PB.createPoint(new BigInteger("714114B762F2FF4A7912A6D2AC58B9B5C2FCFE76DAEB7129", 16), 
										   new BigInteger("29C41E568B77C617EFE5902F11DB96FA9613CD8D03DB08DA", 16));
			BigInteger n = new BigInteger("40000000000000000000000069A779CAC1DABC6788F7474F", 16);
            BigInteger h = BigInteger.valueOf(2);

            return new X9ECParameters(m191PB, P, n, h, null);
        }
    };
			
    static X9ECParametersHolder m233PB = new X9ECParametersHolder()
    {
    	protected X9ECParameters createParameters()
        {
			ECCurve m233PB = new ECCurve.F2m(233, 1, 4, 9, BigInteger.ONE, new BigInteger("06973B15095675534C7CF7E64A21BD54EF5DD3B8A0326AA936ECE454D2C", 16));
			ECPoint P = m233PB.createPoint(new BigInteger("3FCDA526B6CDF83BA1118DF35B3C31761D3545F32728D003EEB25EFE96", 16), 
										   new BigInteger("9CA8B57A934C54DEEDA9E54A7BBAD95E3B2E91C54D32BE0B9DF96D8D35", 16));
			BigInteger n = new BigInteger("1000000000000000000000000000013E974E72F8A6922031D2603CFE0D7", 16);
            BigInteger h = BigInteger.valueOf(2);

            return new X9ECParameters(m233PB, P, n, h, null);
        }
    };
			
    static X9ECParametersHolder m257PB = new X9ECParametersHolder()
    {
    	protected X9ECParameters createParameters()
        {
			ECCurve m257PB = new ECCurve.F2m(257, 12, 0, 0, BigInteger.ZERO, new BigInteger("1CEF494720115657E18F938D7A7942394FF9425C1458C57861F9EEA6ADBE3BE10", 16));
			ECPoint P = m257PB.createPoint(new BigInteger("02A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB7", 16), 
										   new BigInteger("10686D41FF744D4449FCCF6D8EEA03102E6812C93A9D60B978B702CF156D814EF", 16));
			BigInteger n = new BigInteger("800000000000000000000000000000006759213AF182E987D3E17714907D470D", 16);
            BigInteger h = BigInteger.valueOf(4);

            return new X9ECParameters(m257PB, P, n, h, null);
        }
    };
			
    static X9ECParametersHolder m307PB = new X9ECParametersHolder()
    {
    	protected X9ECParameters createParameters()
        {
			ECCurve m307PB = new ECCurve.F2m(307, 2, 4, 8, BigInteger.ONE, new BigInteger("393C7F7D53666B5054B5E6C6D3DE94F4296C0C599E2E2E241050DF18B6090BDC90186904968BB", 16));
			ECPoint P = m307PB.createPoint(new BigInteger("216EE8B189D291A0224984C1E92F1D16BF75CCD825A087A239B276D3167743C52C02D6E7232AA", 16), 
										   new BigInteger("5D9306BACD22B7FAEB09D2E049C6E2866C5D1677762A8F2F2DC9A11C7F7BE8340AB2237C7F2A0", 16));
			BigInteger n = new BigInteger("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC079C2F3825DA70D390FBBA588D4604022B7B7", 16);
            BigInteger h = BigInteger.valueOf(2);

            return new X9ECParameters(m307PB, P, n, h, null);
        }
    };
			
    static X9ECParametersHolder m367PB = new X9ECParametersHolder()
    {
    	protected X9ECParameters createParameters()
        {
			ECCurve m367PB = new ECCurve.F2m(367, 21, 0, 0, BigInteger.ONE, new BigInteger("43FC8AD242B0B7A6F3D1627AD5654447556B47BF6AA4A64B0C2AFE42CADAB8F93D92394C79A79755437B56995136", 16));
			ECPoint P = m367PB.createPoint(new BigInteger("324A6EDDD512F08C49A99AE0D3F961197A76413E7BE81A400CA681E09639B5FE12E59A109F78BF4A373541B3B9A1", 16), 
										   new BigInteger("1AB597A5B4477F59E39539007C7F977D1A567B92B043A49C6B61984C3FE3481AAF454CD41BA1F051626442B3C10", 16));
			BigInteger n = new BigInteger("40000000000000000000000000000000000000000000009C300B75A3FA824F22428FD28CE8812245EF44049B2D49", 16);
            BigInteger h = BigInteger.valueOf(2);

            return new X9ECParameters(m367PB, P, n, h, null);
        }
    };
			
    static X9ECParametersHolder m431PB = new X9ECParametersHolder()
    {
    	protected X9ECParameters createParameters()
        {
			ECCurve m431PB = new ECCurve.F2m(431, 1, 3, 5, BigInteger.ONE, new BigInteger("03CE10490F6A708FC26DFE8C3D27C4F94E690134D5BFF988D8D28AAEAEDE975936C66BAC536B18AE2DC312CA493117DAA469C640CAF3", 16));
			ECPoint P = m431PB.createPoint(new BigInteger("1A62BA79D98133A16BBAE7ED9A8E03C32E0824D57AEF72F88986874E5AAE49C27BED49A2A95058068426C2171E99FD3B43C5947C857D", 16), 
										   new BigInteger("70B5E1E14031C1F70BBEFE96BDDE66F451754B4CA5F48DA241F331AA396B8D1839A855C1769B1EA14BA53308B5E2723724E090E02DB9", 16));
			BigInteger n = new BigInteger("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF", 16);
            BigInteger h = BigInteger.valueOf(2);

            return new X9ECParameters(m431PB, P, n, h, null);
        }
    };
			
    static X9ECParametersHolder m173ONB = new X9ECParametersHolder()
    {
    	protected X9ECParameters createParameters()
        {
			ECCurve m173ONB = new ECCurve.F2m(173, 0, 0, 0, BigInteger.ZERO, new BigInteger("043D7E139319F43BA00944915740E1E6651B06E278C7", 16));
			ECPoint P = m173ONB.createPoint(new BigInteger("0A3B8B8D704089B24318CAA51917CB6E424B4E6DEA56", 16), 
										    new BigInteger("005A43D5EE1F400349CF35150C74F119A39145F0CB08", 16));
			BigInteger n = new BigInteger("800000000000000000000189B4E67606E3825BB2831", 16);
            BigInteger h = BigInteger.valueOf(4);

            return new X9ECParameters(m173ONB, P, n, h, null);
        }
    };
			
    static X9ECParametersHolder m179ONB = new X9ECParametersHolder()
    {
    	protected X9ECParameters createParameters()
        {
			ECCurve m179ONB = new ECCurve.F2m(179, 0, 0, 0, BigInteger.ONE, new BigInteger("19C9EBC4FD8308193D3A61762C547C82F2E6B2182CBCB", 16));
			ECPoint P = m179ONB.createPoint(new BigInteger("11F4112265410477159E0D3E39BC4AC4ADE43B21B66B9", 16), 
										    new BigInteger("2CA5F0B34C61A86216F13766591CB266E2819EE582B3C", 16));
			BigInteger n = new BigInteger("3FFFFFFFFFFFFFFFFFFFFFFB981960435FE5AB64236EF", 16);
            BigInteger h = BigInteger.valueOf(2);

            return new X9ECParameters(m179ONB, P, n, h, null);
        }
    };
			
    static X9ECParametersHolder m191ONB = new X9ECParametersHolder()
    {
    	protected X9ECParameters createParameters()
        {
			ECCurve m191ONB = new ECCurve.F2m(191, 0, 0, 0, BigInteger.ONE, new BigInteger("13871C9D29D6CEEA740FD57444F72FDBAE559C13A1E31EF8", 16));
			ECPoint P = m191ONB.createPoint(new BigInteger("7159E0D3E39BC4AC4ADE43B21B66B94F2AF25ABEEB1D85D3", 16), 
										    new BigInteger("57E45D546BE6201E9705E029535D009D31F51D81E18226BE", 16));
			BigInteger n = new BigInteger("40000000000000000000000069A779CAC1DABC6788F7474F", 16);
            BigInteger h = BigInteger.valueOf(2);

            return new X9ECParameters(m191ONB, P, n, h, null);
        }
    };
			
    static X9ECParametersHolder m233ONB = new X9ECParametersHolder()
    {
    	protected X9ECParameters createParameters()
        {
			ECCurve m233ONB = new ECCurve.F2m(233, 0, 0, 0, BigInteger.ONE, new BigInteger("080F920952A702C75B704A424C018EEA55AA44664F3A003E0962D4F9A8E", 16));
			ECPoint P = m233ONB.createPoint(new BigInteger("0A0823B8ACF069F1CDE256256F21D90DB35CA795792D5F758EC2E9992FB", 16), 
										    new BigInteger("19DAE222AF326D33AFB7761953F624A23D3EB1CA7A1C300F0AA9953CA85", 16));
			BigInteger n = new BigInteger("1000000000000000000000000000013E974E72F8A6922031D2603CFE0D7", 16);
            BigInteger h = BigInteger.valueOf(2);

            return new X9ECParameters(m233ONB, P, n, h, null);
        }
    };
			
    static X9ECParametersHolder m431ONB = new X9ECParametersHolder()
    {
    	protected X9ECParameters createParameters()
        {
			ECCurve m431ONB = new ECCurve.F2m(431, 0, 0, 0, BigInteger.ONE, new BigInteger("53FB7AF7B4407000A6F226AD6BAD28378646BD83F1F940810A4C19536EE65E53F40F973F2F06C5E80EFE3B43651BD5FF8B06BA5F9299", 16));
			ECPoint P = m431ONB.createPoint(new BigInteger("2020182CFCD7C724157B363D4ABFD4C16251773C595D4E5C88572FA9D5EBB58142326448C08D3EE3E17E40B835D3090DCFBA7C5ADEA6", 16), 
										    new BigInteger("18E1B6EFB28EEF8A1F9C1859ED57C74CA747E4E1A60294C005D1920E80903A432929855828DD7F21714F837E119A044987F00110ADAD", 16));
			BigInteger n = new BigInteger("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF", 16);
            BigInteger h = BigInteger.valueOf(2);

            return new X9ECParameters(m431ONB, P, n, h, null);
        }
    };

    static final Hashtable curves = new Hashtable();
    
    static void defineCurve(ASN1ObjectIdentifier oid, X9ECParametersHolder holder)
    {
        curves.put(oid, holder);
    }
    
    static
    {
    	defineCurve(UAObjectIdentifiers.m163PB, m163PB);
    	defineCurve(UAObjectIdentifiers.m167PB, m167PB);
    	defineCurve(UAObjectIdentifiers.m173PB, m173PB);
    	defineCurve(UAObjectIdentifiers.m179PB, m179PB);
    	defineCurve(UAObjectIdentifiers.m191PB, m191PB);
    	defineCurve(UAObjectIdentifiers.m233PB, m233PB);
    	defineCurve(UAObjectIdentifiers.m257PB, m257PB);
    	defineCurve(UAObjectIdentifiers.m307PB, m307PB);
    	defineCurve(UAObjectIdentifiers.m367PB, m367PB);
    	defineCurve(UAObjectIdentifiers.m431PB, m431PB);
    	
    	defineCurve(UAObjectIdentifiers.m173ONB, m173ONB);
    	defineCurve(UAObjectIdentifiers.m179ONB, m179ONB);
    	defineCurve(UAObjectIdentifiers.m191ONB, m191ONB);
    	defineCurve(UAObjectIdentifiers.m233ONB, m233ONB);
    	defineCurve(UAObjectIdentifiers.m431ONB, m431ONB);
    }
    
    /**
     * return the X9ECParameters object for the named curve represented by
     * the passed in object identifier. Null if the curve isn't present.
     *
     * @param oid an object identifier representing a named curve, if present.
     */
    public static X9ECParameters getByOID(
        ASN1ObjectIdentifier oid)
    {
        X9ECParametersHolder holder = (X9ECParametersHolder)curves.get(oid);
        return holder == null ? null : holder.getParameters();
    }
}
