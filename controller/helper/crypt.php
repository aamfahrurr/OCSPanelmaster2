<?php

namespace Helper;

class Crypt {

    private $key;

    function __construct($key){
        $this->setKey($key);
    }

    public function encrypt($encrypt){
        $kunci = $this->key;
        if(mb_strlen($kunci,'8bit') !==32){
            throw new Exception("Needs a 256-bit key!");
        }
        $p_ivfnal = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $p_ebsfrs = base64_encode($domain);
        $p_efirst = "Palhea Encoder First Step - ".serialize($p_ebsfrs);
        $p_ebsscd = base64_encode($p_efirst);
        //$p_ecrtiv = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC),MCRYPT_DEV_URANDOM);
        $p_enckey = pack('H*', $kunci);
        $p_ehhmac = hash_hmac('sha256', $p_ebsscd, substr($kunci, -32));
        //$p_pencry = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $p_enckey, $p_ebsscd . $p_ehhmac, MCRYPT_MODE_CBC, $p_ecrtiv);
        $p_pencry = openssl_encrypt($p_ebsscd . $p_ehhmac,'aes-256-cbc',$p_enckey,OPENSSL_RAW_DATA,$p_ivfnal);
        $p_ebsscd = base64_encode($p_pencry) . '|' . base64_encode($p_ivfnal);
        $p_esecnd = "Palhea Encoder Final Step - ".serialize($p_ebsscd);
        $p_efinal = base64_encode($p_esecnd);
        $encoded = $p_efinal;
        return $encoded;
    }

    public function decrypt($decrypt){
        $kunci = $this->key;
        if(mb_strlen($kunci,'8bit') !==32){
            throw new Exception("Needs a 256-bit key!");
        }
        $p_dbsfrs = base64_decode($decrypt);
        $p_dstrfr = str_replace('Palhea Encoder Final Step - ','',$p_dbsfrs);
        $p_dunsrf = unserialize($p_dstrfr);
        $p_dvaria = explode('|', $p_dunsrf.'|');
        $p_denval = base64_decode($p_dvaria[0]);
        $p_ivfnal = base64_decode($p_dvaria[1]);
        if(strlen($p_ivfnal)!==openssl_cipher_iv_length('aes-256-cbc')){ throw new Exception("Kode Tidak Dapat Diterjemahkan!"); }
        $p_enckey = pack('H*', $kunci);
        $p_dencry = trim(openssl_decrypt($p_denval, 'aes-256-cbc',$p_enckey,OPENSSL_RAW_DATA,$p_ivfnal));
        $p_dehmac = substr($p_dencry, -64);
        $p_dehcry = substr($p_dencry,0,-64);
        $p_ehhmac = hash_hmac('sha256', $p_dehcry, substr($kunci, -32));
        if($p_dehmac !== $p_ehhmac){throw new Exception("Kode Tidak Dapat Diterjemahkan!");}
        $p_dbsscd = base64_decode($p_dehcry);
        $p_dstrsc = str_replace('Palhea Encoder First Step - ','',$p_dbsscd);
        $p_dunsrf = unserialize($p_dstrsc);
        $p_dfinal = base64_decode($p_dunsrf);
        $decrypted = $p_dfinal;	
        return $decrypted;
    }

    public function setKey($key){
        if(ctype_xdigit($key) && strlen($key) === 64){
            $this->key = $key;
        }else{
            trigger_error('Invalid key. Key must be a 32-byte (64 character) hexadecimal string.', E_USER_ERROR);
        }
    }

}
