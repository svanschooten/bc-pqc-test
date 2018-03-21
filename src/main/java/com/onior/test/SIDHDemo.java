package com.onior.test;


import sidh.F2elm;
import sidh.SIDHKeyExchange;
import sidh.SIDHKeyPair;
import sidh.SIDHPublicKey;

public class SIDHDemo {

    private static final String jsPub = "18324B2D34F901E0524C3728F8B6B584D90CDBABE71E0B18CC75DD369C2332256CB08BE3CCEE7DE99C38067E2671054F0B423C4FC4E6CDB51D652D519FD87DBFA4BEADFAF853BC9C2B2BDB00C89D58B091584D435AF5BE5785B5D00C4E51000074AF7346F6361BD7557D48D78CC81210BE80E968358D3A191CB96C97E59280726F41262A890F84D38C5CA5FE5A87A598264FACBC67BA7BFECE273EBD5402BDBAFDE2CF0D684FEBCD01D1D1F9B77B41FC066069AB10168E5304290717B16B0000518DB815BF19E0964EC4CD750DA12CE13F1B5B56860670CB93810A531E530C57A1BFC1934CA4A4C801BC0C8E4D64F8DF35C3364C82878B127C0B32E8F7AB663796C7190A0BE238692004D40D49258BEB16C4A17AF10536CBAA1277ED0335000016E229FDCEA1D090FD4DD37DA839B77274DAEC009824CA57420073644FCEA1F0B3D63052EDE6546CC3E0C49807A4926A2C71AA8AD9E2A47681F1F5216A83E00748B8DEC29BCFAF3427D0A3A3B486AC65C212F60C22FEAC64F87D49ADD15900002D3FC238ADCA4263633A3CF8DD9683F3EDD4EC3E498702B195F647763D64090A108994BE4F690C84CECD1D28CD83C0E637C44036FEDDAEB8A2AF5E99AA4F3DBB0C660F82AB867ECAD75D258212043FA662A24241FFCDD3C1F1007574F24500002C8AFFEBD09B1CDBCE8664BB463E659A9CDDB6C3E0FAD8777CC6F996F4D132E4DF00DC505D84F90B924C8B1F38D80945843C7AA6DEDCC442126CA334B9EBDAA76C4861F2FAF830DB1D3FE65A7C2EBA8879C8EA82415AAD87A02847E9B930000042D55AA475F0D08CB6B4F5CA29BD4CDFECAFA7D664EF9AA53653A936DC0276464893AD8A46718C6B947EB3B77C52E0B6B9243B08E79BA34863AD76D3FFFAA537D2FF595126056481D999F45BA5E0301B006C50AC95FD68547CE72D32850A0000BB46BA5694F22AF39103E62B7A9B119C2CB034D107186F63E7B2DA62A0A2AF43751211186794DEA302727A9D12E05C62F827B47B916A524FB262220ABC087DA74C961BA762BF2C435CE8FEB039B9C0DB547484219A9D5349B1D2DFA8D02800006C3E784352A5854C3433047E59246CBF486EE670C64B3FE2526331BD23ED4AAD9689AA1FFE64B2F0BC6B87C964DEFA275A48DD628532EBBBBBDFBC908616B233ABA36E632DC56B66686A37FBB15D74AA98F18C4FAA7BB63112ACEAAC64060000CE9AD5FED91AE659B0CDFA850BADD30FA7F9784B0D2574607CA6F20DBBF5284015422C3680E1036AE4E293AD0616D3EFE158428DA0568BEB804074F1F459600E6EE1E9D3B3FBBDE0347AB31B6D0BFFF89982C178A4171E4B3B95A4C690110000C612DDD255D7D6F9C2FF77A6689B869F9B64DCB4F58AD8E6F1BF94A59DA2934228342ABA14578BB2199F505B356B6D628E7F4AC89DA054F028AE1AEEA1DE11709C6F27E4620EFF98A79A43D2457D25731E9F6B094FFDC2C3D65A346C5F290000BA1616AD5031980AA7612C02986507126AAFC62993FF2C63098F8FCC9C81E1F1F7514A377665EA83AA9E06D9024C653E6EA3487CBB309200632DB72476D3DB179E15740532B4F9D5F1791DE41B76F9C8A9579711BA00478514759FB9A1280000";

    public static void run() {
        SIDHKeyExchange kex = new SIDHKeyExchange();
        SIDHKeyPair keyPair = kex.generateKeyPair (SIDHKeyExchange.PARTYB);
        SIDHPublicKey publicKey = keyPair.getPublicKey();
        System.out.println("SIDH public key (hex): \n" + Util.bytes2hex(publicKey.serialize()));
        System.out.println("SIDH public key (bytes): \n" + bytes2string(publicKey.serialize()));

        SIDHPublicKey otherPublicKey = new SIDHPublicKey(Util.hex2bytes(jsPub));
        F2elm sharedSecret = kex.calculateAgreementB (keyPair.getPrivateKey(), otherPublicKey);
        System.out.println("Shared secret (hex): \n" + Util.bytes2hex(sharedSecret.toByteArray()));
        System.out.println("Shared secret (bytes): \n" + bytes2string(sharedSecret.toByteArray()));
        System.out.println(" ");
    }

    private static String bytes2string(byte[] bytes) {
        String s = "";
        for (byte b : bytes) {
            s += b + ",";
        }
        return s.substring(0, s.length() - 1);
    }
}