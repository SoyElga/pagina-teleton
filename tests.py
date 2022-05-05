import unittest
from ECDSA_keyGenerator import *
from signVerify import *
from hashlib import sha1,sha224,sha256,sha384,sha512
from curve_data import P_256
class RFC6979_P_256(unittest.TestCase):

    def test_publicKey(self):
        '''verifica que la clave publica de la curva coincida con lo definido por el RFC6979'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        self.assertEqual(public_key(P_256(),private_key).Q, (0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6,
        0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299), "La clave publica no coincide con la clave esperada")



    def test_sha1signature(self):
        '''Verifica el proceso de firma, y que la firma coincida con lo definido por el RFC6979
        usando SHA1 y el mensaje sample'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("sample")
        RFC6979_k=0x882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4
        RFC6979_r=0x61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32
        RFC6979_s=0x6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB
        self.assertEqual(sign_doc(private_key,P_256(),message,sha1(),RFC6979_k),(RFC6979_r,RFC6979_s))

    def test_sha224signature(self):
        '''Verifica el proceso de firma, y que la firma coincida con lo definido por el RFC6979
        usando SHA224 y el mensaje sample'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("sample")
        RFC6979_k = 0x103F90EE9DC52E5E7FB5132B7033C63066D194321491862059967C715985D473
        RFC6979_r = 0x53B2FFF5D1752B2C689DF257C04C40A587FABABB3F6FC2702F1343AF7CA9AA3F
        RFC6979_s = 0xB9AFB64FDC03DC1A131C7D2386D11E349F070AA432A4ACC918BEA988BF75C74C
        self.assertEqual(sign_doc(private_key,P_256(),message,sha224(),RFC6979_k),(RFC6979_r,RFC6979_s))


    def test_sha256signature(self):
        '''Verifica el proceso de firma, y que la firma coincida con lo definido por el RFC6979
        usando SHA256 y el mensaje sample'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("sample")
        RFC6979_k=0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
        RFC6979_r=0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
        RFC6979_s=0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
        self.assertEqual(sign_doc(private_key,P_256(),message,sha256(),RFC6979_k),(RFC6979_r,RFC6979_s))


    def test_sha384signature(self):
        '''Verifica el proceso de firma, y que la firma coincida con lo definido por el RFC6979
        usando SHA384'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("sample")
        RFC6979_k = 0x09F634B188CEFD98E7EC88B1AA9852D734D0BC272F7D2A47DECC6EBEB375AAD4
        RFC6979_r = 0x0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719
        RFC6979_s = 0x4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954
        self.assertEqual(sign_doc(private_key,P_256(),message,sha384(),RFC6979_k),(RFC6979_r,RFC6979_s))

    def test_sha512signature(self):
        '''Verifica el proceso de firma, y que la firma coincida con lo definido por el RFC6979
        usando SHA512'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("sample")
        RFC6979_k = 0x5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5
        RFC6979_r = 0x8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00
        RFC6979_s = 0x2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE
        self.assertEqual(sign_doc(private_key,P_256(),message,sha512(),RFC6979_k),(RFC6979_r,RFC6979_s))




    def test_sha1signature_2(self):
        '''Verifica el proceso de firma, y que la firma coincida con lo definido por el RFC6979
        usando SHA1 y el mensaje test'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("test")
        RFC6979_k = 0x8C9520267C55D6B980DF741E56B4ADEE114D84FBFA2E62137954164028632A2E
        RFC6979_r = 0x0CBCC86FD6ABD1D99E703E1EC50069EE5C0B4BA4B9AC60E409E8EC5910D81A89
        RFC6979_s = 0x01B9D7B73DFAA60D5651EC4591A0136F87653E0FD780C3B1BC872FFDEAE479B1
        self.assertEqual(sign_doc(private_key,P_256(),message,sha1(),RFC6979_k),(RFC6979_r,RFC6979_s))

    def test_sha224signature_2(self):
        '''Verifica el proceso de firma, y que la firma coincida con lo definido por el RFC6979
        usando SHA224'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("test")
        RFC6979_k = 0x669F4426F2688B8BE0DB3A6BD1989BDAEFFF84B649EEB84F3DD26080F667FAA7
        RFC6979_r = 0xC37EDB6F0AE79D47C3C27E962FA269BB4F441770357E114EE511F662EC34A692
        RFC6979_s = 0xC820053A05791E521FCAAD6042D40AEA1D6B1A540138558F47D0719800E18F2D
        self.assertEqual(sign_doc(private_key,P_256(),message,sha224(),RFC6979_k),(RFC6979_r,RFC6979_s))


    def test_sha256signature_2(self):
        '''Genera y verifica la firma del mensaje usando SHA256'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("test")
        RFC6979_k = 0xD16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0
        RFC6979_r = 0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367
        RFC6979_s = 0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083
        self.assertEqual(sign_doc(private_key,P_256(),message,sha256(),RFC6979_k),(RFC6979_r,RFC6979_s))

    def test_sha384signature_2(self):
        '''Verifica el proceso de firma, y que la firma coincida con lo definido por el RFC6979
        usando SHA384'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("test")
        RFC6979_k = 0x16AEFFA357260B04B1DD199693960740066C1A8F3E8EDD79070AA914D361B3B8
        RFC6979_r = 0x83910E8B48BB0C74244EBDF7F07A1C5413D61472BD941EF3920E623FBCCEBEB6
        RFC6979_s = 0x8DDBEC54CF8CD5874883841D712142A56A8D0F218F5003CB0296B6B509619F2C
        self.assertEqual(sign_doc(private_key,P_256(),message,sha384(),RFC6979_k),(RFC6979_r,RFC6979_s))

    def test_sha512signature_2(self):
        '''Verifica el proceso de firma, y que la firma coincida con lo definido por el RFC6979
        usando SHA512'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("test")
        RFC6979_k = 0x6915D11632ACA3C40D5D51C08DAF9C555933819548784480E93499000D9F0B7F
        RFC6979_r = 0x461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04
        RFC6979_s = 0x39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55
        self.assertEqual(sign_doc(private_key,P_256(),message,sha512(),RFC6979_k),(RFC6979_r,RFC6979_s))



    def test_sha1_verification(self):
        '''Genera y verifica la firma del mensaje sample usando SHA1'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("sample")
        RFC6979_k=0x882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4
        publickey=public_key(P_256(),private_key)
        signature=sign_doc(private_key,P_256(),message,sha1(),RFC6979_k)
        self.assertTrue((verify(signature,P_256(),publickey,message,sha1())))

    def test_sha224_verification(self):
        '''Genera y verifica la firma del mensaje sample usando SHA256'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("sample")
        RFC6979_k=0x103F90EE9DC52E5E7FB5132B7033C63066D194321491862059967C715985D473
        publickey=public_key(P_256(),private_key)
        signature=sign_doc(private_key,P_256(),message,sha224(),RFC6979_k)
        self.assertTrue((verify(signature,P_256(),publickey,message,sha224())))


    def test_sha256_verification(self):
        '''Genera y verifica la firma del mensaje sample usando SHA256'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("sample")
        RFC6979_k=0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
        publickey=public_key(P_256(),private_key)
        signature=sign_doc(private_key,P_256(),message,sha256(),RFC6979_k)
        self.assertTrue((verify(signature,P_256(),publickey,message,sha256())))


    def test_sha384_verification(self):
        '''Verifica el proceso de firma, y que la firma coincida con lo definido por el RFC6979
        usando SHA384'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("sample")
        RFC6979_k = 0x09F634B188CEFD98E7EC88B1AA9852D734D0BC272F7D2A47DECC6EBEB375AAD4
        publickey=public_key(P_256(),private_key)
        signature=sign_doc(private_key,P_256(),message,sha384(),RFC6979_k)
        self.assertTrue((verify(signature,P_256(),publickey,message,sha384())))

    def test_sha512_verification(self):
        '''Verifica el proceso de firma, y que la firma coincida con lo definido por el RFC6979
        usando SHA512'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("sample")
        RFC6979_k = 0x5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5
        publickey=public_key(P_256(),private_key)
        signature=sign_doc(private_key,P_256(),message,sha512(),RFC6979_k)
        self.assertTrue((verify(signature,P_256(),publickey,message,sha512())))

    def test_sha1_verification_2(self):
        '''Genera y verifica la firma del mensaje test usando SHA1'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("test")
        RFC6979_k=0x882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4
        publickey=public_key(P_256(),private_key)
        signature=sign_doc(private_key,P_256(),message,sha1(),RFC6979_k)
        self.assertTrue((verify(signature,P_256(),publickey,message,sha1())))

    def test_sha224_verification_2(self):
        '''Genera y verifica la firma del mensaje test usando SHA256'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("test")
        RFC6979_k=0x103F90EE9DC52E5E7FB5132B7033C63066D194321491862059967C715985D473
        publickey=public_key(P_256(),private_key)
        signature=sign_doc(private_key,P_256(),message,sha224(),RFC6979_k)
        self.assertTrue((verify(signature,P_256(),publickey,message,sha224())))


    def test_sha256_verification_2(self):
        '''Genera y verifica la firma del mensaje test usando SHA256'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("test")
        RFC6979_k=0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
        publickey=public_key(P_256(),private_key)
        signature=sign_doc(private_key,P_256(),message,sha256(),RFC6979_k)
        self.assertTrue((verify(signature,P_256(),publickey,message,sha256())))

    def test_sha384signature_2(self):
        '''Verifica el proceso de firma, y que la firma coincida con lo definido por el RFC6979
        usando SHA384'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("test")
        RFC6979_k = 0x16AEFFA357260B04B1DD199693960740066C1A8F3E8EDD79070AA914D361B3B8
        publickey=public_key(P_256(),private_key)
        signature=sign_doc(private_key,P_256(),message,sha384(),RFC6979_k)
        self.assertTrue((verify(signature,P_256(),publickey,message,sha384())))

    def test_sha512signature_2(self):
        '''Verifica el proceso de firma, y que la firma coincida con lo definido por el RFC6979
        usando SHA512'''
        private_key=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        message=str.encode("test")
        RFC6979_k = 0x6915D11632ACA3C40D5D51C08DAF9C555933819548784480E93499000D9F0B7F
        publickey=public_key(P_256(),private_key)
        signature=sign_doc(private_key,P_256(),message,sha512(),RFC6979_k)
        self.assertTrue((verify(signature,P_256(),publickey,message,sha512())))




if __name__ == '__main__':
    unittest.main(verbosity=2)
    