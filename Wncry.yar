rule WannaCry_Varian_Gwff {
    meta:
        author = "123Aaaakh"
        date = "2026-07-03"
        threat_level = "Critical"
        sample_sha256 = "abf48b77091e81dfe1c0528bbfbf48cf3f551ac269b32e8e667449657cbe4697" 
        sample_md5 = "700b42582dca1ae9e0aad8a5dd7f9022"

    strings:
        $url_killswitch = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwff.com" ascii
        $password_zip   = "WNcry@2ol7" ascii
        $file_komponen1 = "t.wnry" ascii
        $file_komponen2 = "c.wnry" ascii
        $nop_bypass_hex = { 85 FF 90 90 }

    condition:
        uint16(0) == 0x5A4D and // Harus file Windows EXE (MZ header)
        (
            $url_killswitch or
            $password_zip or
            all of ($file_komponen*) or
            $nop_bypass_hex
        )
}
