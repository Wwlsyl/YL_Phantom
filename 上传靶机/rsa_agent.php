<?php
class RSA {
    private static $PRIVATE_KEY = <<<EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAq6RHhCFeLBWe7n7UgkCF/EIFpQPp818gnLm/CVvH0By7wuvl
bu80mDhqfJyPHK0XgT/Tc9e1Fv7IGU2fFjgbPXYF85n0wBcGUY+jR4GEufo/ONsO
awLxX213AnO7hJrFRmS+IQoh2fMi655cn1yYJ03Hp8xpZ2gSUQVsyIjwu6Cpc3sO
mmr8jQUJQJER7CUPeIfZD7fd0jTJAiU8xdDOGKpqhpzIb0QNX57jVtOTAlJfOcFO
Z488LAqVk6QXe3Sq8R2MorUpX5l6P9Yygl4UCLpnPT6rqrJe6Rg3Is4McZh9RMG/
qDkdd8YA1HJQpyxprMMcleDcqmjxMb4TRL3elQIDAQABAoIBAAJJJgWprxgdspfg
+wIAC3i8RVh4+J7b07Kam6NrhDnuhAaYvx2u1E+5optlt1ctq+w19iIrC3eSrYX+
vWFdnmk/Xt1rXbHILLad19IONL8ISNrAOg0tRRsc+VKASY0+xWVGVqzYdnJxVTP3
kCq0IDeXxtKie33byjCnhpcWEcSh3cIVzN4hasWmzIknHGpG9RhCawM8tJmUDcbi
AoRJXklX7xPh2+34VWvipsr6iEwhwABnDR5BKCLOEQJ6d6guPMcp5d5ioIHSOpqJ
lcrlg641rRTZ93bvWohGWKYvSk+Ppi3OHHMkUiZGNUt1X1XedlB3bPv70O69cUJi
RNhS7akCgYEA1xv2ftIeFLCGGGWRV1+6nEmy2tyBKxt0mP0PoKxlz+zfbh8UZWD9
hUXbxyDGDZKyQrUK5Aioj6xFlpW7ikeLjxFCalwZSit9g0+JuI+BYnKVbdg7fgDN
DALRH0p/mvzsJcmLMTXMXhNzrzL6RpmyT+MwH8c8U6fIczHHHRKS9M0CgYEAzEUF
azXY7IjNyl7hDmYsmISzCLbaWSqRvOh5cXrovBxUI4tDgrYzWcOmT98iC+CwR0yZ
OTjod0WO7o1sunppvo10BToSClZutFlTyTmu/FGfId2OHz8IKnTL2Gd3lVvAlYh5
bungKL3BGjd0ufotRNqXCQG9a0toil7Y5upxUOkCgYA7i/Qae1P0akFUs5keVNO1
u/kU+QGQy1LlnvgahF7SxkG7nELrJYRIxmPmpb3tt/Q83x0arwLqcsf4vY5i4xdR
DXgTNVeS3qMqHHSFcMRiWlHfTIJ7iQE6F/WH8fmNEALXGwm7H6dpS300vKnnrVhd
IQkLYv3iMoocyWTTOXcQ6QKBgCHJaNQK3A6DskY+20rea5HuoQ5X8FW/TMvKSAwV
IFm89c3LQydjq6q1SdT8O01rpLymVtG4L/tKbhHXIpzVkpgKHZ6ftEwxb640+D7Y
Y7EobwHS+6b/bgJXvz/UHVt/CaOyJyPJW2JhwIbtlUkNsF8rKMA8oXAV0PzSI15O
eN/BAoGAYGG22Ath7A70uW3un+GjU/y/voUke2vqEsvNzlLutVf4N82a6wqpzWWU
S3vp7uhDtK1X1dpmfOxNrJKHHZ7Iq6qf+OKoiUIWEaS8hQaQKuvwx74SMbx/Cgcq
FvuhzZBSgjd2AyTD3SIsCRUvjV4dnfKWYP7K18GbKZmQSTgdTcU=
-----END RSA PRIVATE KEY-----
EOF;
    private static $PUBLIC_KEY = <<<EOF
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq6RHhCFeLBWe7n7UgkCF
/EIFpQPp818gnLm/CVvH0By7wuvlbu80mDhqfJyPHK0XgT/Tc9e1Fv7IGU2fFjgb
PXYF85n0wBcGUY+jR4GEufo/ONsOawLxX213AnO7hJrFRmS+IQoh2fMi655cn1yY
J03Hp8xpZ2gSUQVsyIjwu6Cpc3sOmmr8jQUJQJER7CUPeIfZD7fd0jTJAiU8xdDO
GKpqhpzIb0QNX57jVtOTAlJfOcFOZ488LAqVk6QXe3Sq8R2MorUpX5l6P9Yygl4U
CLpnPT6rqrJe6Rg3Is4McZh9RMG/qDkdd8YA1HJQpyxprMMcleDcqmjxMb4TRL3e
lQIDAQAB
-----END PUBLIC KEY-----
EOF;
    private static function getPrivateKey() { return openssl_pkey_get_private(self::$PRIVATE_KEY); }
    private static function getPublicKey()  { return openssl_pkey_get_public(self::$PUBLIC_KEY); }
    public static function privateEncrypt($data) {
        $res = ''; foreach (str_split($data, 245) as $chunk) {
            openssl_private_encrypt($chunk, $enc, self::getPrivateKey()); $res .= $enc;
        } return $res ? base64_encode($res) : null;
    }
    public static function publicEncrypt($data) {
        $res = ''; foreach (str_split($data, 245) as $chunk) {
            openssl_public_encrypt($chunk, $enc, self::getPublicKey()); $res .= $enc;
        } return $res ? base64_encode($res) : null;
    }
    public static function privateDecrypt($data) {
        $res = ''; foreach (str_split(base64_decode($data), 256) as $chunk) {
            openssl_private_decrypt($chunk, $dec, self::getPrivateKey()); $res .= $dec;
        } return $res ?: null;
    }
    public static function publicDecrypt($data) {
        $res = ''; foreach (str_split(base64_decode($data), 256) as $chunk) {
            openssl_public_decrypt($chunk, $dec, self::getPublicKey()); $res .= $dec;
        } return $res ?: null;
    }
}
$rsa = new RSA(); $encrypt = isset($_GET['encrypt']); $data = file_get_contents("php://input");
if ($encrypt) { echo $rsa->privateEncrypt($data); }
else { $ret = $rsa->privateDecrypt($data); if (!$ret) $ret = $rsa->publicDecrypt($data); echo $ret ?: 'DECRYPT_FAILED'; }
