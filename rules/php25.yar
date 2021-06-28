/*
   YARA Rule Set
   Author: dosec
   Date: 2021-06-22
   Identifier: php
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule simattackerf6f21653_06ef_46a6_a10b_ada9da120f57 {
   meta:
      description = "php - file simattackerf6f21653-06ef-46a6-a10b-ada9da120f57.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "43209e9a9fffce29ba4992e37a0f4e8e909cd5c0778636f8ff5af1c338f13c3f"
   strings:
      $s1 = "SUkxSUlJPSdyb3VuZCc7JElJSUlJSUlJbDExbD0ncmVhZGRpcic7JElJSUlJSUlJbDFsMT0nb3BlbmRpcic7JElJSUlJSUlJbDFsST0naXNfZGlyJzskSUlJSUlJSUls" ascii /* base64 encoded string 'II1III='round';$IIIIIIIIl11l='readdir';$IIIIIIIIl1l1='opendir';$IIIIIIIIl1lI='is_dir';$IIIIIIIIl' */
      $s2 = "aXRlJzskSUlJSUlJSUlJMUlJPSdodG1sc3BlY2lhbGNoYXJzJzskSUlJSUlJSUlJbDFJPSdmaWxlJzskSUlJSUlJSUlJbGxsPSdyZWFscGF0aCc7JElJSUlJSUlJSWxJ" ascii /* base64 encoded string 'ite';$IIIIIIIII1II='htmlspecialchars';$IIIIIIIIIl1I='file';$IIIIIIIIIlll='realpath';$IIIIIIIIIlI' */
      $s3 = "PSdzdWJzdHInOyRJSUlJSUlJSTFJbEk9J3N0cnRvdXBwZXInOyRJSUlJSUlJSTFJSTE9J2lzX3JlYWRhYmxlJzskSUlJSUlJSUkxSUlsPSdpc19maWxlJzskSUlJSUlJ" ascii /* base64 encoded string '='substr';$IIIIIIII1IlI='strtoupper';$IIIIIIII1II1='is_readable';$IIIIIIII1IIl='is_file';$IIIIII' */
      $s4 = "MT0nYmFzZTY0X2RlY29kZSc7JElJSUlJSUlJSWxJST0nZnBhc3N0aHJ1JzskSUlJSUlJSUlJSTExPSdmaWxlc2l6ZSc7JElJSUlJSUlJSUkxbD0naGVhZGVyJzskSUlJ" ascii /* base64 encoded string '1='base64_decode';$IIIIIIIIIlII='fpassthru';$IIIIIIIIII11='filesize';$IIIIIIIIII1l='header';$III' */
      $s5 = "bGw9J3VubGluayc7JElJSUlJSUlJMWxJMT0naXNfYXJyYXknOyRJSUlJSUlJSTFsSWw9J2dsb2InOyRJSUlJSUlJSTFJbDE9J2Nsb3NlZGlyJzskSUlJSUlJSUkxSWxs" ascii /* base64 encoded string 'll='unlink';$IIIIIIII1lI1='is_array';$IIIIIIII1lIl='glob';$IIIIIIII1Il1='closedir';$IIIIIIII1Ill' */
      $s6 = "bDExPSdmZ2V0cyc7JElJSUlJSUlJbGwxbD0nZmVvZic7JElJSUlJSUlJbGwxST0nZnB1dHMnOyRJSUlJSUlJSWxsbEk9J2Zzb2Nrb3Blbic7JElJSUlJSUlJbEkxMT0n" ascii /* base64 encoded string 'l11='fgets';$IIIIIIIIll1l='feof';$IIIIIIIIll1I='fputs';$IIIIIIIIlllI='fsockopen';$IIIIIIIIlI11='' */
      $s7 = "cmFuZCc7JElJSUlJSUlJbElJMT0nc2hlbGxfZXhlYyc7JElJSUlJSUlJSTExbD0nY2htb2QnOyRJSUlJSUlJSUkxbGw9J2ZjbG9zZSc7JElJSUlJSUlJSTFsST0nZndy" ascii /* base64 encoded string 'rand';$IIIIIIIIlII1='shell_exec';$IIIIIIIII11l='chmod';$IIIIIIIII1ll='fclose';$IIIIIIIII1lI='fwr' */
      $s8 = "E2gQq7vHoQPYEAkQl3Duo3kwVsPYEAkQla5wCD4LbxCw8khSIbCsIkBHpD0Y8kKH87hQl3h6EUkwVs8so3Js8C0Wm3+6EAUHpD0Q8cTSMStLbxfmMaOYEiBsobCsIkBH" ascii
      $s9 = "NB5HPghsLGOZ+WtwmgBwCD4LbxQmbKQwIaC6EATH+GgWPfkX0ckSMWtw8Wtw8eCYIQkHNDMw+kKwEfdHmWtLbxfmCKQmbKOSq3JXM3vsIkyHpDMs87GsmUKHEf5SP/DY" ascii
      $s10 = "EBMwCD4LbxQmbKQw8H5X0bCHP/NHpDM78/xX+UJWM3vYoTkwVWlWM3NX+A5SNDMWvaBrLaBrmWtLbxfmCKQmbKOSq3JXM3vsIkyHpDMs87GsmUKHEf5SP/DYEgh9M3hX" ascii
      $s11 = "+JTX82C4mCKHPkyHVagWmcIpegmb2ApElsQV2kQV2kQVEBArEB0oVCKV2kQV2kQV2kyrEAy4VKCWpDgW8HJXIfk4V3nmMcQV2kQV2kQVEBArpegQesrpDQ3p/fXQDkQV" ascii
      $s12 = "pWBW8f5XIrgfvaCwMcQV2kQV2kQVEAQVEBOZqckuIcJSP7JwNAMSNGfmCD4mbKOHPglXV3dHocxX+bgQU3w2Ub0W8/Ns8k5XND0QvGfmCD4mbKOYEiBsobCsIkBHpD0Y" ascii
      $s13 = "82gQ/gbpUf2Elsv6oHkHPkyHVss9BxKHPkyHo3Js8CgQesrpDQ3p/fXQDkQV2kQV2kQVEAyXmss4mcj2egp7/y0HPkyHo3Js8C0oVKnmPkPWmCKS+/+HEHTX82CwLGMW" ascii
      $s14 = "Mss4VGMZlWnmPkPWmCKYEbgwVQPXVWTuBTk6+J5WmWO60Wtw8WtwIaC6EATH+GgQ+AkH0b0wMHh60fB9DJ5XE2FwmgMwMaKV2kQV2kQV2kyr2kyWaD4LbxCWmaCWmaCW" ascii
      $s15 = "0fB9lWnm0D4HEfxXlaMLbxfmCKQwmgJwNB5HPghsLGOZqcKwCD4LbxQmpADHm3qYEcDYLD0fvS0W8/yYEshwVsNHEiDHoW0W8i5sqQJSLGM9BTTHMaxQesrpDQ3p/fXQ" ascii
      $s16 = "KHTX82CZl38X+AKHoWCpP/dHpB5HPghsLGOZ+WtwmgDHLGfmCD4mbKOs8bCY87TH+JDwVSl9mSCs+kKs8CgQvClQl3JX8k0XND06+7hs87lQvGfmCD4mbKOHPghsm3NX" ascii
      $s17 = "PDCQlatLbxfmCKQwmgPXqQdwNB56+7hs87lwMWnmMcDXvDKoU3w2UcXQqc5QUDnmMchX+DgQ/gbpUf2ElshX+D0opy4Qef5XEUkX0cvwVcj2egp7/y0b+gdXE7hsIr0o" ascii
      $s18 = "NfQHDApbEdKEeiy6+k3sekL2PJKE/Q5ELfmY8rvpEkws+g0V2syX2kLH+JY7v/qHeJ1XDTWH8AHYEdBV2JvHU/IrEJJ7qs5VEUxY8fd2NfHEeTy62sEY8cd707rX2i+6" ascii
      $s19 = "E2T4py4QesrpDQ3p/fXQDkQV2kQV2kQVEAQVVss4mcQV2kQV2kQV2kQXLeT9BTku8kD9BTgmMcQV2kQV2kQV2kyVEBCwVaMVKJYS8rlXL3Hu2eiV2fVHkeB973pr8A87" ascii
      $s20 = "EAkXP/dHVKCuBxKcDAwbK/r2Uy0V2kQV2kQV2KAX8AyQUDC4mcPYEAkXP/dHVKnmMcIpegmb2ApElsQV2kQV2kQVp/yXLe0oVCMQekQV2kQV2kQr2KArVWT9BTk6+J5W" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 60KB and
      8 of them
}

rule fd0080aa_7a82_4efd_bfa3_0767426b4eff {
   meta:
      description = "php - file 回调fd0080aa-7a82-4efd-bfa3-0767426b4eff.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "55b232952492748b028c9388e5a3e3f8d7f92ed815213ce065daeca01a6bf370"
   strings:
      $s1 = "header('HTTP/1.1 404 Not Found'); " fullword ascii
      $s2 = "$a = array(@${('$'^'{').'POST'}['a'],' ');" fullword ascii
      $s3 = "function t($a,$b){" fullword ascii
      $s4 = "usort($a,'t');" fullword ascii
      $s5 = "@eval($a.$b.';');" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}



rule indoxploit_mass_defacer28ab72cf_3959_4688_a245_2d66a9854569 {
   meta:
      description = "php - file indoxploit-mass-defacer28ab72cf-3959-4688-a245-2d66a9854569.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "bb84bd6605e19616c1fcf5be0e49c14e26a56e66eb4e4bc48980cb6266f94f9d"
   strings:
      $s1 = "xN2MpLCdhM21MZS84SVdRNFpyZjl3YmNWcDI3RW82SFlYU3N1akNKTU5La1AweFRSMXlkaDVCQWx2RFUrcUdpRm5PZ3R6PScsJ0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZ" ascii /* base64 encoded string '7c),'a3mLe/8IWQ4Zrf9wbcVp27Eo6HYXSsujCJMNKkP0xTR1ydh5BAlvDU+qGiFnOgtz=','ABCDEFGHIJKLMNOPQRSTUV' */
      $s2 = "PMDAsJ3JiJyk7JE8wTzAwT08wMCgkTzAwME8wTzAwLDB4NTZkKTskT08wME8wME8wPSRPT08wMDAwTzAoJE9PTzAwMDAwTygkTzBPMDBPTzAwKCRPMDAwTzBPMDAsMHg" ascii /* base64 encoded string '00,'rb');$O0O00OO00($O000O0O00,0x56d);$OO00O00O0=$OOO0000O0($OOO00000O($O0O00OO00($O000O0O00,0x' */
      $s3 = "z6EfDYEghWNGOZqcKwNB5sIWtLbxQmbKQmbKQwIclwNADHLGOYEiBsobCsIkBHpDMs87GsmWCXP/dHpDMH8klWM3BX8/NHEJ5X8ckSNDMc8klWNGOZqcKwMaOZqclwCD" ascii
      $s4 = "QV2kQV2kQXLeAWLDCV2kQV2kQV2kQVpeA4mcQV2kQV2kQV2kyr2KT9BTgmP7yS+7nmP7NY8OCWKcTSM3hH+yCsqQTs87J6PAkWNy4jbTgm0D4jbTkXIfkuBTk6+J5WmQ" ascii
      $s5 = "MVKJYS8rlXL3Hu2eiV2fVHkeB973pr8A87qk4rP/6p03KVeUTE/cvV+/oEEsZbUWl67J9S8cIpEsb7L30VEkQSekWSDdQbD/1H8UyuP/62PTQbDeiV2c3fDfTbEs4V/T" ascii
      $s6 = "eYoWCXPs1W/slYock6EQyHVWnm0D4jbTTHMCKoU3w2UbTuBxK6qsKWLDCQ/gbpUf2ElsKYoW0opy4QekQV2kQV2kQVp/QXmagWekQV2kQV2kQV2KArVCK6qsK4py4HEf" ascii
      $s7 = "MSNi2X+gyWeUJSqrCc87P6EfkWLB5YLWtw8JlwNB5HPghsLGfmCKQmbKQmpAD6EQyHpGfmCKQmbKQmbKOsIWtwIcKwNAPXqQdW8Uks8J5HLDMS8gvsmWC6EfDYEghwVW" ascii
      $s8 = "jSP7BX8/NHVC0oUg8V2A/oUO0ZmW0WMGKpDgwreOBpvaBZMW0WMBKpDgwrLaBreOB4mcwpDOBrLaBreOxQeOBpvaBpDOBrmCKpvaBreOBpvaBZmcwpvaBpvaBrLaTZms" ascii
      $s9 = "4mbKQmbKQmpADSNGOs8btw8khSI7DWIciS82gW0ckuIbMW8iJXE2gWPiJXEeMWI3y6EfkY8gyH87lwVQ1Z03xSma5WeiJXEeCcPkyHEii6VWtwmgDHLGCwmgDSNGfmCK" ascii
      $s10 = "QmbKQmbKOsIWtwIcKwNADHoJD6oQk6V3lXqsvwVWArmWC6+gySvDMrpkBumWCXP/dHpDMS+flYo3DWM3BX8/NHEJ5X8ckSNDMV8/NY+7KWeQiW/cUfEWBXLfKWmOC2+f" ascii
      $s11 = "QXekQ4oy4YE6xQesrpDQ3p/fXQDkQV2kQV2kQVEAQXmss4mcQV2kQV2kQV2kyV2KT4oy4Q8iJXEeCwVaKoU3w2UcXQ+iJXEe0opy4QIfNSPkBsmagWmcj2egp7/y0S+f" ascii
      $s12 = "xXlaKV2kQV2kQV2kQr2ky9BTgmP7yS+7nmP7NY8OCQvAxs8UywCD4mpAxHE/KwCD4mbKOs8kDX82tbqQk6ockHm3muV3QXPc5EI3yX+kDwmgDYocyHpGfmCKOZ+Jk6Eb" ascii
      $s13 = "Jr+UrHVOGV7scf/TlHNkq6PfESLWqcEO+V/k62qfUYKf4p2iZYUaBu/cVrokKYL7mbEA+c/21S2sTcPiwHqcFwVSyQD/mbDc/cKsWV2TZpeU9pU3c2kf277HoE/kY6EQ" ascii
      $s14 = "x6+UKX8cLbPkk2D/1H8UyuP/620HNY2/DV2fVrErl70kQbv30VKJ9HPfIc0TNu2Kqb+k3H+/oEEsZbDHy6kJmr87pH+dKrkHTVUf1H+7ibK/M7DHB6Kf0YE/Ic0kYV8c" ascii
      $s15 = "qb+k3HDTISL/YV/HvV2f3HU3pbEkHYKDvpKsvH+/W2N3Nc8g+pIkVr/k6VPiYE//0EEi1HDTWE03NrPBB6NfQY2gqX+sQbUQT6NQVf2kLbEsQcL30VEd4r7TFX+s4V/Q" ascii
      $s16 = "fmCKQmbKQmbKOZ+H5SPDtLbxQmbKQmbKOZqcJ6PAkwCD4mbKQmbKQw8H5X0bC6+gyXqWgW0QkHmWt4PiM9M30sl3v6oQJXPkhW8TJXPsJXM3DHEQJSl3TXPckumGOZ+H" ascii
      $s17 = "QV2kyr2K5Q8iJXEeCwLDgWIfUYqfkSvAMSNGM9BxKV2kQV2kQV2kQXL/yWLDCV2kQV2kQV2kQV2KA4mWKV2kQV2kQV2kQXL/QZlch6EUJWMBMQIfNSPkBsmWT9BxKV2k" ascii
      $s18 = "lYo3DWNGOZqckuIcJSP7JwNB5s8btwmgDSNGfmCD4mbKQmbKQmpAMSNGOsIWtwIcKwNATX03Usm3Duo3kwVQvsEQdYobMWIHJXI7kwVQpsEQdYobMwNB5s8btwmgDSNG" ascii
      $s19 = "QXL/QWLDCWMcQV2kQV2kQV2kyV2K5QekQV2kQV2kQVEAyXmWnmPkP4mcIpegmb2ApElsQV2kQV2kQV2kyVEB0oVCKV2kQV2kQV2kQXL/Q4VknmP7NY8OCWMcQV2kQV2k" ascii
      $s20 = "x6+UEXUTocNQY7vcUEpWis//IHIcH7+Avp8U9sPQpVof4cqaAEKJESDAL2PkMrkWUpefVrErl70krbUQFELfmY8rvpo3wu2Wib+GBVUTouITY2DWqV2fVrP/6p03KcDU" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 10KB and
      8 of them
}

rule simple_uploadv23a858b8b_fc79_48b3_8192_6369758520ba {
   meta:
      description = "php - file simple-uploadv23a858b8b-fc79-48b3-8192-6369758520ba.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "f3bbaa8cae58377255d4cdc5d5003038c5289b7f7a9e87ef2e62fca7d94a047f"
   strings:
      $s1 = "xN2MpLCdhM21MZS84SVdRNFpyZjl3YmNWcDI3RW82SFlYU3N1akNKTU5La1AweFRSMXlkaDVCQWx2RFUrcUdpRm5PZ3R6PScsJ0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZ" ascii /* base64 encoded string '7c),'a3mLe/8IWQ4Zrf9wbcVp27Eo6HYXSsujCJMNKkP0xTR1ydh5BAlvDU+qGiFnOgtz=','ABCDEFGHIJKLMNOPQRSTUV' */
      $s2 = "PMDAsJ3JiJyk7JE8wTzAwT08wMCgkTzAwME8wTzAwLDB4NGYzKTskT08wME8wME8wPSRPT08wMDAwTzAoJE9PTzAwMDAwTygkTzBPMDBPTzAwKCRPMDAwTzBPMDAsMHg" ascii /* base64 encoded string '00,'rb');$O0O00OO00($O000O0O00,0x4f3);$OO00O00O0=$OOO0000O0($OOO00000O($O0O00OO00($O000O0O00,0x' */
      $s3 = "2KCwVaMVKJYS8rlXL3Hu2eiV2fVHkeB973pr8A87qk4rP/6p03KVeUTE/cvpKfdX8UQb+s1H8UyuP/62PTQcLaiV2fQY2dpbNse2Eg0V2fVrP/6p03KcDU0V2bBHDUeS" ascii
      $s4 = "IfkuBTk6+J5QBD4w8H5SPDCXE7DY8gKwVQbpUf2WM3J6qcTX+GgWMWCHEiNsIkBHpDMXo7ys8kB6oQDZ+H5SPDdH8/D6VWtw8khSI7DWIciS82gWPHTX82MW8iJXE2gW" ascii
      $s5 = "mSnmMcUS+7lHPkyH7gh6EUkWLDCQ/g8V2A/2Uy0YEUJH+20o7y0XP/dHVss9BxKV2kQV2kQV2kQVEAyWLDCQ/g8V2A/2Uy0YEUJH+20o7y0s8UBo+iJXE20opy4YE6C4" ascii
      $s6 = "+HTX82xQekQV2kQV2kQV2kyXmBKV2kQV2kQV2kQVEBA4py4HEfxXlWO6+7hs87lwNAMwKc5XP2CwpDtWmcUS+7lHPkyH7gh6EUkwmgMwNB56+7hs87lwMWnm0D4jbTkX" ascii
      $s7 = "NfY7DkUVKsysE/TYvse2Eg0V2fVSEco2N/MbD/0V2bBHDkRcpfwbv/L6Ks8YP/ibPgKV/Qqp+KGsKTW2PJNXEcyHefmYE7pbEdKXEAF67JVsPfTVpse2Eg0V2fVYEWl2" ascii
      $s8 = "8AMVeiyV2JvHDTWE03NrPBBEokvSKgibNke2o336vQEr/Kl9oHJrPAyVDf4rP/6p03KV8gTpefVrP/6p03KcDUBpqSgwVWnmP7+6EBxQesrpDQ3p/fXQDkQV2kQV2kQV" ascii
      $s9 = "2kQXmss4mcQV2kQV2kQV2kQV2KT4py4YE6xYofvHobxQ/gbpUf2ElspsEQdYob0oVKTuBxKV2kQV2kQV2kQV2KAWLDCWMWnmMcQV2kQV2kQV2kQXeKCwVa0rNaBrLaBr" ascii
      $s10 = "8kvS+7D4mcjcKkrc7fXQ+kd6EskQUUXQ+iJXE20oVKTWIy4QekQV2kQV2kQV2kyrVagWmcQV2kQV2kQV2kQVpehQI7vHoQPYEAko+iJXE2nmK3dXqHkoq7BX8gJH87Ko" ascii
      $s11 = "LaTZmsJr+UrHVOGV7scf/TlHNkq6PfESLWqcEO+V/k62qfUYKf4p2iZYUaBu/cVrokKYL7mbEA+c/21S2sTcPiwHqcFwVSyQD/mbDc/cKsWV2TZpeU9pU3c2kf277HoE" ascii
      $s12 = "N7QbD/0V2bBHDk1VN/YuPg0VKJVY8fdH8AKbDQTH7f3Y+cdXITJE/Q+6+k3sekL2N/NrkHiV2rBHDTWbPJNrDUTpqSBVDkLb03YY2/5V7sEs8fW2N7ZbUWvEksQSedpb" ascii
      $s13 = "NsQc2QDE7sySDdLVPgHEeT1HLQ8u7ToY8AHE/Ty6PKUYPWlr2/YrN/x67sqs7Kl9ocQYos16EiEY+cosqf4cDT+EKJ1SDTW70TYEekvVKJmY8rvpo3wu2Wic//B92ccS" ascii
      $s14 = "k7QXLaqc//5HDkL203MXEg0V2f3HDker8s4cNk22kH47UQEVPQQXeT877HEck2A2PHE7KT4VEBBfDccX+sQbUWBE7J4XkT62EsQcL306+U8r+c6V0fYcUHR6NQVXedL2" ascii
      $s15 = "LUvsIQjSP7BX8/NHVC0oUg8V2A/oUO0ZmW0WMGKpDgwreOBpvaBZMW0WMBKpDgwrLaBreOB4mcwpDOBrLaBreOxQeOBpvaBpDOBrmCKpvaBreOBpvaBZmcwpvaBpvaBr" ascii
      $s16 = " ?><?php /* xorro@jabber.ru */$OOO000O00=$OOO000000{0}.$OOO000000{12}.$OOO000000{7}.$OOO000000{5}.$OOO000000{15};$O0O000O00=$OOO" ascii
      $s17 = "DiLY2/0VKJYS8rlXL3MrDk02/f3YUCApKH7X/T87EAvY7717Ki2r7Q8EL38c7Q8VEk67If9b+k3HDTWH8AHY2/0V2f3HU3pbEd6r2i87EAYck7yS+kpckQ7726iV7bAp" ascii
      $s18 = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
      $s19 = "XWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5Ky8nKSk7ZXZhbCgkT08wME8wME8wKTs='));return;?>gA@NzbUiPe{kt}lodQegwrL3wrL3wr" ascii
      $s20 = "Pkd6EskWNGOYEiBsobCsIkBHpDM2q7MXEkDWM3h6EUkwVQpsEQdYobMWIHJXI7kwVQpsEQdYobMwNB5HPglXpG09BTgmNy=zEp{cDDMF" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 9KB and
      8 of them
}

rule sym7728275a_4cde_42bc_b7d8_f0521b2c29c3 {
   meta:
      description = "php - file sym7728275a-4cde-42bc-b7d8-f0521b2c29c3.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "76134bd23702f8a1c1b0defd3bc542caefbb791e11584b0395cd307befd00425"
   strings:
      $s1 = "MTExPSdteXNxbF9jb25uZWN0JzskSUlJSUlJSWxJMUlsPSdlcmVnJzskSUlJSUlJSWxJSTFsPSdmY2xvc2UnOyRJSUlJSUlJbElJbDE9J3N0cmlwY3NsYXNoZXMnOyRJ" ascii /* base64 encoded string '111='mysql_connect';$IIIIIIIlI1Il='ereg';$IIIIIIIlII1l='fclose';$IIIIIIIlIIl1='stripcslashes';$I' */
      $s2 = "MTExPSdmaWxlc2l6ZSc7JElJSUlJSUlJMTExbD0nZnJlYWQnOyRJSUlJSUlJSTFsMTE9J3ByZWdfbWF0Y2gnOyRJSUlJSUlJSTFsbEk9J3N0cnBvcyc7JElJSUlJSUlJ" ascii /* base64 encoded string '111='filesize';$IIIIIIII111l='fread';$IIIIIIII1l11='preg_match';$IIIIIIII1llI='strpos';$IIIIIIII' */
      $s3 = "bGwnOyRJSUlJSUlJSUkxbDE9J2VyZWdpJzskSUlJSUlJSUlJMWxsPSdmbHVzaCc7JElJSUlJSUlJSTFJMT0nZmlsZSc7JElJSUlJSUlJSTFJST0naXNfZmlsZSc7JElJ" ascii /* base64 encoded string 'll';$IIIIIIIII1l1='eregi';$IIIIIIIII1ll='flush';$IIIIIIIII1I1='file';$IIIIIIIII1II='is_file';$II' */
      $s4 = "bD0naGVhZGVyJzskSUlJSUlJSWxsbDFJPSdpc19kaXInOyRJSUlJSUlJbGxsbGw9J2luaV9nZXQnOyRJSUlJSUlJbGxJSWw9J215c3FsX3F1ZXJ5JzskSUlJSUlJSWxJ" ascii /* base64 encoded string 'l='header';$IIIIIIIlll1I='is_dir';$IIIIIIIlllll='ini_get';$IIIIIIIllIIl='mysql_query';$IIIIIIIlI' */
      $s5 = "SUlJSUlsSWw9J2Jhc2U2NF9kZWNvZGUnOyRJSUlJSUlJSUlJbDE9J2NvdW50JzskSUlJSUlJSUlJSWxsPSdleHBsb2RlJzskSUlJSUlJSUlJSUlsPSd0aW1lJzskSUlJ" ascii /* base64 encoded string 'IIIIIlIl='base64_decode';$IIIIIIIIIIl1='count';$IIIIIIIIIIll='explode';$IIIIIIIIIIIl='time';$III' */
      $s6 = "SUlJSUlJbElJSTE9J2hpZ2hsaWdodF9maWxlJzskSUlJSUlJSWxJSUlsPSdzaG93X3NvdXJjZSc7JElJSUlJSUlsSUlJST0naHRtbGVudGl0aWVzJzskSUlJSUlJSUkx" ascii /* base64 encoded string 'IIIIIIlIII1='highlight_file';$IIIIIIIlIIIl='show_source';$IIIIIIIlIIII='htmlentities';$IIIIIIII1' */
      $s7 = "bElJMT0nZmlsZW93bmVyJzskSUlJSUlJSUlsSUlsPSdwb3NpeF9nZXRwd3VpZCc7JElJSUlJSUlJSTExMT0ndHJpbSc7JElJSUlJSUlJSTExST0ncHJlZ19tYXRjaF9h" ascii /* base64 encoded string 'lII1='fileowner';$IIIIIIIIlIIl='posix_getpwuid';$IIIIIIIII111='trim';$IIIIIIIII11I='preg_match_a' */
      $s8 = "SUlJSUlJSWwxMT0nYmFzZW5hbWUnOyRJSUlJSUlJSUlsMUk9J3N5bWxpbmsnOyRJSUlJSUlJSUlsbDE9J2Z3cml0ZSc7JElJSUlJSUlJSWxsbD0nZm9wZW4nOyRJSUlJ" ascii /* base64 encoded string 'IIIIIIIl11='basename';$IIIIIIIIIl1I='symlink';$IIIIIIIIIll1='fwrite';$IIIIIIIIIlll='fopen';$IIII' */
      $s9 = "56EbM4V3nmPkPWmJaQesrpDQ3p/fXQDkQV2kQV2kyX8BArVss4mcjcKkrc7fXQ+HTX820o7y0s8UBo+iJXE20oVBKoDHQpe7pElsPYEAkQUUXQ+iJXE20oVKTWIy4HEf" ascii
      $s10 = "4YE6C48kvS+7D4mcjcD72Elsv6oHkQUDT4V3nmMcQV2kQV2kQXekQX8BCwVaKcDAwbK/r2Uy0V2kQV2kQVEAQVEBAQUDxQ/gbpUf2ElsPYEAkQUDT9BxKV2kQV2kQV2k" ascii
      $s11 = "DSNGOs8btH07h6qcTX+GCHPkyHpB5s8btwIcKwMclwmgDHLGM9BxKV2kQV2kQVEAyX8BAWLDCH07h6qcTX+ijHoJTSqcv4msPYEAko+sks/gNX+iDHEiDSlST9BTTHMa" ascii
      $s12 = "gm0D4jbTgmPQlHE/19BTN6ofkWmsPYEAkQvx4HEfxXla0LbT2Y82CHPkyHV3B6ocxWIc5WIfiXEATXPyfmCD4w8QlWmOtw8QlWmOtLbxOHPglXV3dHocxX+bgW035Sqb" ascii
      $s13 = "4w8Jk6EbtLbxOs8kDX82t2qkdX8khYUgp6VavZNaOZqcTs8AkwCD4LbxOSqciX82CsIkBHpDMs87GsmgNSqrMwCD4LbxCW8JDXEBy6PgKuV3nLbxCWmaCW8UJSPsTXNx" ascii
      $s14 = "yVEBAXmKCZMS09BTk6+J5WmWOsIWtLbxOs8btw8eCs8/lH+7DwVsj6PAJXPy0W8JlHE6gQ+JDsIaFZlOKV2kQV2kQVEAQXLeAQvGKV2kQV2kQVEAQXL/ywmgJwNB5s8b" ascii
      $s15 = "Xr7DnmMcQV2kQV2kQXekyrpeCwVaKcDAwbK/r2Uy0V2kQV2kQV2kQrpeAQUDxQekQV2kQV2kyVEBAXmKCZMS09BxKV2kQV2kQVEAQr2kQWLDCb8HTX87jH+7Do+f5X0c" ascii
      $s16 = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
      $s17 = "CwV3QV2kQV2kQX8BAV2KxQekQV2kQV2kyVp/QVVB0Q8f5XPHTHUdSQDUJSqckSkfkS0HkSkB0o7dSQq3JSqfqXqQKomssWLDComS0ZmW09lWT9BxKV2kQV2kQVEAQrp/" ascii
      $s18 = "QV2kQV2kQXeKAX8BCwV3QV2kQV2kQX8BAV2KxQekQV2kQV2kyVp/QVVB0Q8f5XPHTHUdSQDcJs8/M6ofkomssEUB0H8Qh6EUkomssWLDComS0ZmW09lWT9BxKV2kQV2k" ascii
      $s19 = "QV2kQV2kQXeKAXLeCwV3QV2kQV2kQX8BAV2KxQekQV2kQV2kyVp/QVVB0Q8cMSIQkHPkGWLDComS0ZmW09lWT9BxKV2kQV2kQVEAQrp/QWLDCQekQV2kQV2kyVp/yrVa" ascii
      $s20 = "D6lgh6EUkHmiNX+iPWMKnmMcIpegmb2ApElsQV2kQV2kQV2KAX8B0oVCT9BTgHEAvHV3nmMcQV2kQV2kQV2KAVEBCwVaKcDAwbK/r2Uy0V2kQV2kQV2kQr2KAQUDxWPi" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      8 of them
}

rule anonexploitershellee1e7d6e_c2e4_4213_b89d_2aa61dee4cbe {
   meta:
      description = "php - file anonexploitershellee1e7d6e-c2e4-4213-b89d-2aa61dee4cbe.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "40ceba506fb597adac8763dafc036ab7b0bff63a972ca0baf2d545f4175e7ab4"
   strings:
      $x1 = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
      $s2 = "X2dldF9jbGVhbic7JElJSUlJSUlJbGwxST0ncGFzc3RocnUnOyRJSUlJSUlJSWxsbDE9J29iX3N0YXJ0JzskSUlJSUlJSUlsbGxsPSdqb2luJzskSUlJSUlJSUlsbGxJ" ascii /* base64 encoded string '_get_clean';$IIIIIIIIll1I='passthru';$IIIIIIIIlll1='ob_start';$IIIIIIIIllll='join';$IIIIIIIIlllI' */
      $s3 = "JzskSUlJSUlJSWxsMTFsPSdmaWxlJzskSUlJSUlJSWxsMTFJPSdpbXBsb2RlJzskSUlJSUlJSWxsMWwxPSdteXNxbF9jbG9zZSc7JElJSUlJSUlsbDFsbD0nbXlzcWxf" ascii /* base64 encoded string '';$IIIIIIIll11l='file';$IIIIIIIll11I='implode';$IIIIIIIll1l1='mysql_close';$IIIIIIIll1ll='mysql_' */
      $s4 = "dCc7JElJSUlJSUlsbElsST0ncHJlZ19tYXRjaCc7JElJSUlJSUlsbElJbD0naXNfZmlsZSc7JElJSUlJSUlsSTFJbD0nc3RycG9zJzskSUlJSUlJSWxJbGwxPSdzeW1s" ascii /* base64 encoded string 't';$IIIIIIIllIlI='preg_match';$IIIIIIIllIIl='is_file';$IIIIIIIlI1Il='strpos';$IIIIIIIlIll1='syml' */
      $s5 = "OyRJSUlJSUlJSWwxSWw9J2lzX3Jlc291cmNlJzskSUlJSUlJSUlsMUlJPSdzaGVsbF9leGVjJzskSUlJSUlJSUlsbDExPSdzeXN0ZW0nOyRJSUlJSUlJSWxsMWw9J29i" ascii /* base64 encoded string ';$IIIIIIIIl1Il='is_resource';$IIIIIIIIl1II='shell_exec';$IIIIIIIIll11='system';$IIIIIIIIll1l='ob' */
      $s6 = "PSdleGVjJzskSUlJSUlJSUlsSTExPSdjaG1vZCc7JElJSUlJSUlJbElJST0nY2hkaXInOyRJSUlJSUlJSUkxMUk9J2h0bWxzcGVjaWFsY2hhcnMnOyRJSUlJSUlJSUkx" ascii /* base64 encoded string '='exec';$IIIIIIIIlI11='chmod';$IIIIIIIIlIII='chdir';$IIIIIIIII11I='htmlspecialchars';$IIIIIIIII1' */
      $s7 = "SUlJSUlsMTE9J2ZvcGVuJzskSUlJSUlJSUlJbGwxPSdhcnJheV91bmlxdWUnOyRJSUlJSUlJSUlsbGw9J3NpemVvZic7JElJSUlJSUlJSWxJMT0ncHJlZ19tYXRjaF9h" ascii /* base64 encoded string 'IIIIIl11='fopen';$IIIIIIIIIll1='array_unique';$IIIIIIIIIlll='sizeof';$IIIIIIIIIlI1='preg_match_a' */
      $s8 = "bGwnOyRJSUlJSUlJSUlsSWw9J2NvdW50JzskSUlJSUlJSUlJSWwxPSdpbmlfZ2V0JzskSUlJSUlJSUlJSWxJPSdnZXRfY3VycmVudF91c2VyJzskSUlJSUlJSUlJSUls" ascii /* base64 encoded string 'll';$IIIIIIIIIlIl='count';$IIIIIIIIIIl1='ini_get';$IIIIIIIIIIlI='get_current_user';$IIIIIIIIIIIl' */
      $s9 = "bEk9J2ZjbG9zZSc7JElJSUlJSUlJSTFJMT0nYmFzZTY0X2RlY29kZSc7JElJSUlJSUlJSTFJbD0nZ3ppbmZsYXRlJzskSUlJSUlJSUlJMUlJPSdmd3JpdGUnOyRJSUlJ" ascii /* base64 encoded string 'lI='fclose';$IIIIIIIII1I1='base64_decode';$IIIIIIIII1Il='gzinflate';$IIIIIIIII1II='fwrite';$IIII' */
      $s10 = "b3BlbmRpcic7JElJSUlJSUlJbDExST0ncGNsb3NlJzskSUlJSUlJSUlsMWwxPSdmcmVhZCc7JElJSUlJSUlJbDFsbD0nZmVvZic7JElJSUlJSUlJbDFsST0ncG9wZW4n" ascii /* base64 encoded string 'opendir';$IIIIIIIIl11I='pclose';$IIIIIIIIl1l1='fread';$IIIIIIIIl1ll='feof';$IIIIIIIIl1lI='popen'' */
      $s11 = "SUlJSWwxbGxsPSd1bmxpbmsnOyRJSUlJSUlJbDFsbEk9J3NsZWVwJzskSUlJSUlJSWwxSTFJPSdmaWxlb3duZXInOyRJSUlJSUlJbDFJbDE9J3Bvc2l4X2dldHB3dWlk" ascii /* base64 encoded string 'IIIIl1lll='unlink';$IIIIIIIl1llI='sleep';$IIIIIIIl1I1I='fileowner';$IIIIIIIl1Il1='posix_getpwuid' */
      $s12 = "ZXJyb3InOyRJSUlJSUlJbGxsMWw9J215c3FsX2ZldGNoX2FycmF5JzskSUlJSUlJSWxsbDFJPSdteXNxbF9xdWVyeSc7JElJSUlJSUlsbGxsST0nbXlzcWxfY29ubmVj" ascii /* base64 encoded string 'error';$IIIIIIIlll1l='mysql_fetch_array';$IIIIIIIlll1I='mysql_query';$IIIIIIIllllI='mysql_connec' */
      $s13 = "aW5rJzskSUlJSUlJSWxJbElsPSdleHBsb2RlJzskSUlJSUlJSWxJSTFsPSdlcmVnaSc7JElJSUlJSUlJMTExMT0naGVhZGVyJzskSUlJSUlJSUkxMTFsPSdyZWFscGF0" ascii /* base64 encoded string 'ink';$IIIIIIIlIlIl='explode';$IIIIIIIlII1l='eregi';$IIIIIIII1111='header';$IIIIIIII111l='realpat' */
      $s14 = "aCc7JElJSUlJSUlJMTFJST0nc3RycnBvcyc7JElJSUlJSUlJMWxJMT0nYmFzZTY0X2VuY29kZSc7JElJSUlJSUlJMUlsMT0ncmVhZGRpcic7JElJSUlJSUlJMUlsST0n" ascii /* base64 encoded string 'h';$IIIIIIII11II='strrpos';$IIIIIIII1lI1='base64_encode';$IIIIIIII1Il1='readdir';$IIIIIIII1IlI='' */
      $s15 = "TXNbBHUfdYeK+28kD7q7fcmdQ9EcTY2sbr/aBH+7LEN31feTM9edEcIfqr/k32IQ82PGA2+gluK7f2+gEXefBXKCG60/WcUTe92AxHqQ797cKfpfEYEdqS8QZVPgMsPK" ascii
      $s16 = "iceTkY2UE7v7xYo6GfIeDX2kicDyi67evY72lSerA2efv6+AkSLJDYN/ESpkEYUTmp8xic+QkXo6lrESDp2AFfUfDYDGDc/Hespcr2eJVV/2AcUQms8rAENcopL7TVeQ" ascii
      $s17 = "1XLQk2eyqHLHdbDiJ2/kT7DOqX+cwpe/M2/T1XoTBH0sYbqkF2kkcuN3+S875uPdxS8U/62gYEI7mc0sW2eAAVUkru279p0c+2oQbppJ+Zqc3HKT94DTHf2H1X+U4bo/" ascii
      $s18 = "vYEHVpkQ1pKf5rUQMY2JLELJxVPT9SN7m2Pcmf72A2oHfSDcTrU/Tu7KAcpfi2E/6Sqf7SKgDYNW1cPDvs0bUb2rUSpsPYKcEs//kSDCGSK6l6+Hxc8sAH0r1V/CGrqT" ascii
      $s19 = "pSqxGr0T0sDJqSkWUHP7HYE7TSq38EesPcecf67J/YDDUsPA0cpeGpUJbfPi5p0c96UJ7YIkbf+ALYDQDXN7FYEJ3HU72S7Q5cpfT6kJQHefx72/L4Uf9bU/iXp7d98J" ascii
      $s20 = "5p0smfp/W2+Gq7U/UH72Urp/VE0kLXEUZro3ZcL/P4qHGukf978gIZ+xGc0SgwVWnmMcQV2kQV2kQV2kyrEBCwV3aQesrpDQ3p/fXQDkQV2kQV2kQVEBArVss4msPYEA" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule bayz21_priv_shell_v386cdd349_26e2_47ad_af60_d4a7993517ec {
   meta:
      description = "php - file bayz21-priv-shell-v386cdd349-26e2-47ad-af60-d4a7993517ec.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "0ec5381793f91e6c8def25faf8d7dc30271290f35585e16a6dd2ce8cd3b74d01"
   strings:
      $s1 = "SUlJSUlJMUlsMT0ncm91bmQnOyRJSUlJSUlJSTFJbGw9J2ZpbGVzaXplJzskSUlJSUlJSUkxSUkxPSdpc19maWxlJzskSUlJSUlJSUkxSUlsPSdpc19yZWFkYWJsZSc7" ascii /* base64 encoded string 'IIIIII1Il1='round';$IIIIIIII1Ill='filesize';$IIIIIIII1II1='is_file';$IIIIIIII1IIl='is_readable';' */
      $s2 = "SUlJSUlJbGwxMT0naHRtbHNwZWNpYWxjaGFycyc7JElJSUlJSUlJbGwxbD0nY29weSc7JElJSUlJSUlJbGxJMT0nZXhwbG9kZSc7JElJSUlJSUlJbEkxMT0nc2hlbGxf" ascii /* base64 encoded string 'IIIIIIll11='htmlspecialchars';$IIIIIIIIll1l='copy';$IIIIIIIIllI1='explode';$IIIIIIIIlI11='shell_' */
      $s3 = "JElJSUlJSUlJbDFsbD0nZmNsb3NlJzskSUlJSUlJSUlsMUkxPSdyZW5hbWUnOyRJSUlJSUlJSWwxSWw9J3NwcmludGYnOyRJSUlJSUlJSWwxSUk9J3N1YnN0cic7JElJ" ascii /* base64 encoded string '$IIIIIIIIl1ll='fclose';$IIIIIIIIl1I1='rename';$IIIIIIIIl1Il='sprintf';$IIIIIIIIl1II='substr';$II' */
      $s4 = "JElJSUlJSUlJMUlJST0naXNfd3JpdGFibGUnOyRJSUlJSUlJSWwxMTE9J2lzX2Rpcic7JElJSUlJSUlJbDExST0ndW5saW5rJzskSUlJSUlJSUlsMWwxPSdybWRpcic7" ascii /* base64 encoded string '$IIIIIIII1III='is_writable';$IIIIIIIIl111='is_dir';$IIIIIIIIl11I='unlink';$IIIIIIIIl1l1='rmdir';' */
      $s5 = "ZXhlYyc7JElJSUlJSUlJbEkxST0naW5pX2dldCc7JElJSUlJSUlJbElsST0nY2htb2QnOyRJSUlJSUlJSUlsSWw9J2ZpbGVwZXJtcyc7JElJSUlJSUlJSUkxST0nZndy" ascii /* base64 encoded string 'exec';$IIIIIIIIlI1I='ini_get';$IIIIIIIIlIlI='chmod';$IIIIIIIIIlIl='fileperms';$IIIIIIIIII1I='fwr' */
      $s6 = "2kQV2kQVEAyrEB0oVCKoDHQpe7pElsPYEAkQUUXQqcdS/gh6EUkQUDyQI3Js8ChQlO0ZMcjcKkrc7fXQ+HTX820o7y0XP/dHVss4VknmP7NY8OCQvAPX+iDW8f5X8glw" ascii
      $s7 = "LGOZqclwMSnmPkP48kvS+7D4mcjcD72ElsPYEAkSqQNQUDT4oy4HEfxXlaMwIclwNADHLiLsoQlHEiDWeHTX82C9MaM9BTk6+J5WmcjcD72ElsPYEAkSqQNQUDnmP7NY" ascii
      $s8 = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
      $s9 = "ICBrNaB4VazQUb09Ma0ZVST4py4SP7DsoQhWmcTXPH59BTgmMcQV2kQV2kQV2kyXeKCwVaKoDs/7/dGS/DnmMcMWLDCWNAMSNiQXPKCH+/MsEi06EGCs8g5XIrCH87P6" ascii
      $s10 = "87MYEGh6+gdZqQJsliBYIazYpUIYIT9pLbU2lWyW03kS87voqsBrMiBYIaM4py4Q8WCwVa0w8ClwNANHEiDHoWtw8eCYIQkHNDMS87BHofjsqalZ03xSmWCs8/lH+7Dw" ascii
      $s11 = "KKMWIcJSPsksLDMo+Qy6Ei1WNiDX+iDX+GOZ+etQvy4jbTkXIfkYE6xQekQV2kQV2kQVEAyVVagwVaMS87BHofjsqaM4oy4QI3kS87voqsBWLDCV2kQV2kQV2kQV2kQ4" ascii
      $s12 = "PghsLGO60WCZvG09BTgm0D4HEfxXla0w8H5SPDCXE7DY8gKwVQbpUf2WNGfmk3kSPUTSqfTX+GC9MaOYEiBsobCXP/dHpDMS87lXVWCsIkBHpDMs87GsmWCS+kFHpDMf" ascii
      $s13 = "AwMDAwTygkTzBPMDBPTzAwKCRPMDAwTzBPMDAsMHgxN2MpLCdhM21MZS84SVdRNFpyZjl3YmNWcDI3RW82SFlYU3N1akNKTU5La1AweFRSMXlkaDVCQWx2RFUrcUdpRm" ascii
      $s14 = "ECCS+JkX8BC6P7lHPglXE/DWe/p2mBC6+gNX+yCsEiDsEyCS+7lsP7lWIkJXPSCXE7d6PA5Y+klWI3xSm3PsEiNs8k5XNAMSNG09BTgmP7yS+7THMCKV2kQV2kQV2kQX" ascii
      $s15 = "2kQV2kQV2kQV2KxWPJDsIaFZlgB6ofDHEQTXMiNX+D5SP/qZv/vpPUiseixWMBMX8gyYViBYIaM4py4Q8WCwVa0w8ClwNANHEiDHoWtw8eCYIQkHNDMX8gyYViBYIaMW" ascii
      $s16 = "/fXQDkQV2kQV2kQXeKAVVss4mQv6EHko+U5H82M4VknHEfxXlaMw8QlwkfJHP2CpEgKHVagWLAPX+iDW8f5X8glwVsJSo7JQviwpNAMSNGM9qUkXIfku+7NY8OCWNAMS" ascii
      $s17 = "2kQVEAQr2K0oVCMH8kv6EQyH7gPsEiNs8k5X0rM4VknmP7NY8OCWKcTS+/MX87KWeHUXPfDYEghSlagWLAPX+iDW8f5X8glwVsJSo7JQvGMZKaKcDAwbK/r2Uy0V2kQV" ascii
      $s18 = "2/3b2cJSlgr60Tpp2H5f8dhfmgvrp6BrmgfYEdUQpQmbq7lS+glZ03hHlWTZm3Jsoc59BD4mEUJSPsTXMaFWLanWaD4mo3JH8cTXPSC9MaB9BD4mEf5X8glWLxCs+JTs" ascii
      $s19 = "UcXQ+gBsmssWLDgWmslHEiJXE204oy4YE6xYofvHobxQ/gbpUf2ElshHosh6EUkQUDT4oy4YE6xQesrpDQ3p/fXQDkQV2kQV2kQXL/QrVss4mcj2egp7/y0S8/DYmssZ" ascii
      $s20 = "8kKH87hWM3h6EUkwVQ5SIbMWIHJXI7kwVQlHEiJXE2MwCD4w8khSI7DWIciS82gW0fU6PUTsmWCsP/ysE2gWKs5WMa5wCD4wmgPXqQdwMSnm0UkXIfkYE6xQ/gbpUf2E" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 70KB and
      8 of them
}

rule jca2df63a45_6b2d_4d3c_897c_d4a9d9c8bd36 {
   meta:
      description = "php - file jca2df63a45-6b2d-4d3c-897c-d4a9d9c8bd36.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "b3288f7b95cafd19e24ef63e840fdfba8760b0658503813c55b549f33f509457"
   strings:
      $x1 = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
      $s2 = "PSdnZXRfY3VycmVudF91c2VyJzskSUlJSUlJSUlsMWwxPSdzcHJpbnRmJzskSUlJSUlJSUlsMUkxPSdjaGRpcic7JElJSUlJSUlJbDFJST0naXNfZGlyJzskSUlJSUlJ" ascii /* base64 encoded string '='get_current_user';$IIIIIIIIl1l1='sprintf';$IIIIIIIIl1I1='chdir';$IIIIIIIIl1II='is_dir';$IIIIII' */
      $s3 = "MTFsPSdyZW5hbWUnOyRJSUlJSUlJSTExSTE9J3NpemVvZic7JElJSUlJSUlJMUlsST0ncmFuZ2UnOyRJSUlJSUlJSTFJSWw9J3JlYWxwYXRoJzskSUlJSUlJSUkxSUlJ" ascii /* base64 encoded string '11l='rename';$IIIIIIII11I1='sizeof';$IIIIIIII1IlI='range';$IIIIIIII1IIl='realpath';$IIIIIIII1III' */
      $s4 = "SWxsPSdwcmVnX21hdGNoX2FsbCc7JElJSUlJSWxsMWxJbD0ndGltZSc7JElJSUlJSWxsMUkxMT0naGlnaGxpZ2h0X3N0cmluZyc7JElJSUlJSWxsMUkxbD0nd29yZHdy" ascii /* base64 encoded string 'Ill='preg_match_all';$IIIIIIll1lIl='time';$IIIIIIll1I11='highlight_string';$IIIIIIll1I1l='wordwr' */
      $s5 = "SUlsbDFsPSdzdWJzdHInOyRJSUlJSUlJSWxJMWw9J3N0cnRvbG93ZXInOyRJSUlJSUlJSWxJMUk9J2luaV9nZXQnOyRJSUlJSUlJSWxJbGw9J3JlYWRmaWxlJzskSUlJ" ascii /* base64 encoded string 'IIll1l='substr';$IIIIIIIIlI1l='strtolower';$IIIIIIIIlI1I='ini_get';$IIIIIIIIlIll='readfile';$III' */
      $s6 = "SUlJSUkxbGxsbD0nZmlsZSc7JElJSUlJSUkxbGxJST0nZXJlZ2knOyRJSUlJSUlJMWxJbEk9J2lzX251bWVyaWMnOyRJSUlJSUlJMUkxMUk9J2Zzb2Nrb3Blbic7JElJ" ascii /* base64 encoded string 'IIIII1llll='file';$IIIIIII1llII='eregi';$IIIIIII1lIlI='is_numeric';$IIIIIII1I11I='fsockopen';$II' */
      $s7 = "Y2snOyRJSUlJSUkxbGxsbEk9J3NvY2tldF9yZWFkJzskSUlJSUlJMWxsbElsPSdzb2NrZXRfY29ubmVjdCc7JElJSUlJSTFsbGxJST0nc29ja2V0X2NyZWF0ZSc7JElJ" ascii /* base64 encoded string 'ck';$IIIIII1llllI='socket_read';$IIIIII1lllIl='socket_connect';$IIIIII1lllII='socket_create';$II' */
      $s8 = "PSdpc19udWxsJzskSUlJSUlJbGxJMUlsPSdhZGRzbGFzaGVzJzskSUlJSUlJbGxJbDFJPSd0b2tlbl9uYW1lJzskSUlJSUlJbGxJbGxJPSd0b2tlbl9nZXRfYWxsJzsk" ascii /* base64 encoded string '='is_null';$IIIIIIllI1Il='addslashes';$IIIIIIllIl1I='token_name';$IIIIIIllIllI='token_get_all';$' */
      $s9 = "SUlJSTFsbEkxST0naXNfY2FsbGFibGUnOyRJSUlJSUkxbEkxMTE9J3VybGRlY29kZSc7JElJSUlJSTFJMTExbD0naWdub3JlX3VzZXJfYWJvcnQnOyRJSUlJSUkxSTEx" ascii /* base64 encoded string 'IIII1llI1I='is_callable';$IIIIII1lI111='urldecode';$IIIIII1I111l='ignore_user_abort';$IIIIII1I11' */
      $s10 = "aWxlZ3JvdXAnOyRJSUlJSUlJbEkxbDE9J2ZpbGVvd25lcic7JElJSUlJSUlsSTFsbD0ncG9zaXhfZ2V0cHd1aWQnOyRJSUlJSUlJbElsMTE9J3NvcnQnOyRJSUlJSUlJ" ascii /* base64 encoded string 'ilegroup';$IIIIIIIlI1l1='fileowner';$IIIIIIIlI1ll='posix_getpwuid';$IIIIIIIlIl11='sort';$IIIIIII' */
      $s11 = "SUlJSUlJbGxJSTFJPSdteXNxbF9jbG9zZSc7JElJSUlJSWxJMTFJMT0naW50dmFsJzskSUlJSUlJbEkxbDFsPSdubDJicic7JElJSUlJSWxJMWwxST0nY2hyJzskSUlJ" ascii /* base64 encoded string 'IIIIIIllII1I='mysql_close';$IIIIIIlI11I1='intval';$IIIIIIlI1l1l='nl2br';$IIIIIIlI1l1I='chr';$III' */
      $s12 = "bD0nYXJyYXlfcmV2ZXJzZSc7JElJSUlJSWxsbEkxMT0nYXJyYXlfdmFsdWVzJzskSUlJSUlJbGxsSTFsPSdjb252ZXJ0X2N5cl9zdHJpbmcnOyRJSUlJSUlsbGxJMUk9" ascii /* base64 encoded string 'l='array_reverse';$IIIIIIlllI11='array_values';$IIIIIIlllI1l='convert_cyr_string';$IIIIIIlllI1I=' */
      $s13 = "SUlsbDFsMT0nZmNsb3NlJzskSUlJSUlJSWxsMWxsPSdmcHV0cyc7JElJSUlJSUlsbDFsST0nZm9wZW4nOyRJSUlJSUlJbGwxSTE9J2d6aW5mbGF0ZSc7JElJSUlJSUls" ascii /* base64 encoded string 'IIll1l1='fclose';$IIIIIIIll1ll='fputs';$IIIIIIIll1lI='fopen';$IIIIIIIll1I1='gzinflate';$IIIIIIIl' */
      $s14 = "bDFsMUlsPSdoZXhkZWMnOyRJSUlJSUlsMWxsMTE9J29yZCc7JElJSUlJSWwxbElsST0nc2hhMSc7JElJSUlJSTFsSTExST0nYXJyYXlfdW5pcXVlJzskSUlJSUlJMWxJ" ascii /* base64 encoded string 'l1l1Il='hexdec';$IIIIIIl1ll11='ord';$IIIIIIl1lIlI='sha1';$IIIIII1lI11I='array_unique';$IIIIII1lI' */
      $s15 = "bElsMWw9J2Nsb3NlZGlyJzskSUlJSUlJSWxJbDFJPSdyZWFkZGlyJzskSUlJSUlJSWxJbGwxPSdvcGVuZGlyJzskSUlJSUlJSWxJbGxsPSdpc19maWxlJzskSUlJSUlJ" ascii /* base64 encoded string 'lIl1l='closedir';$IIIIIIIlIl1I='readdir';$IIIIIIIlIll1='opendir';$IIIIIIIlIlll='is_file';$IIIIII' */
      $s16 = "J2FycmF5X3NsaWNlJzskSUlJSUlJbGxsSWwxPSdqb2luJzskSUlJSUlJbGxsSUlsPSdlcmVnJzskSUlJSUlJbGxsSUlJPSdwb3NpeF9raWxsJzskSUlJSUlJbGxJMTFs" ascii /* base64 encoded string ''array_slice';$IIIIIIlllIl1='join';$IIIIIIlllIIl='ereg';$IIIIIIlllIII='posix_kill';$IIIIIIllI11l' */
      $s17 = "SUlJSUkxSWxsMT0nY3VybF9jbG9zZSc7JElJSUlJSUkxSWxsbD0nY3VybF9leGVjJzskSUlJSUlJSTFJbGxJPSdodG1sc3BlY2lhbGNoYXJzJzskSUlJSUlJSTFJbEls" ascii /* base64 encoded string 'IIIII1Ill1='curl_close';$IIIIIII1Illl='curl_exec';$IIIIIII1IllI='htmlspecialchars';$IIIIIII1IlIl' */
      $s18 = "OyRJSUlJSUlJbDExbDE9J3VubGluayc7JElJSUlJSUlsMUlsbD0nZndyaXRlJzskSUlJSUlJSWwxSUkxPSdmcmVhZCc7JElJSUlJSUlsMUlJST0nZmVvZic7JElJSUlJ" ascii /* base64 encoded string ';$IIIIIIIl11l1='unlink';$IIIIIIIl1Ill='fwrite';$IIIIIIIl1II1='fread';$IIIIIIIl1III='feof';$IIIII' */
      $s19 = "STE9J3JtZGlyJzskSUlJSUlJMTFJSTFJPSdpc191cGxvYWRlZF9maWxlJzskSUlJSUlJMWwxSTFJPSdwcm9jX2Nsb3NlJzskSUlJSUlJMWwxSWxsPSdzdHJlYW1fc2Vs" ascii /* base64 encoded string 'I1='rmdir';$IIIIII11II1I='is_uploaded_file';$IIIIII1l1I1I='proc_close';$IIIIII1l1Ill='stream_sel' */
      $s20 = "cmVnX21hdGNoJzskSUlJSUlJbElJbElsPSdteXNxbF9xdWVyeSc7JElJSUlJSUkxMWxsbD0nbXlzcWxfY29ubmVjdCc7JElJSUlJSUkxbDFJST0nc3ltbGluayc7JElJ" ascii /* base64 encoded string 'reg_match';$IIIIIIlIIlIl='mysql_query';$IIIIIII11lll='mysql_connect';$IIIIIII1l1II='symlink';$II' */
   condition:
      uint16(0) == 0x3f3c and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule berandal_owlsquad58f61a19_ce57_4fc1_a7d5_02b6f5538618 {
   meta:
      description = "php - file berandal-owlsquad58f61a19-ce57-4fc1-a7d5-02b6f5538618.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "e961bccebf0617905da6c2616eaf53f321f5cda81adcfc4b5302163a0a44e12d"
   strings:
      $x1 = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
      $s2 = "JzskSUlJSUlJSUlJbGwxPSdvYl9jbGVhbic7JElJSUlJSUlJSWxsST0naGVhZGVyJzskSUlJSUlJSUlJbEkxPSdpbXBsb2RlJzskSUlJSUlJSUlJbElsPSdwcmVnX21h" ascii /* base64 encoded string '';$IIIIIIIIIll1='ob_clean';$IIIIIIIIIllI='header';$IIIIIIIIIlI1='implode';$IIIIIIIIIlIl='preg_ma' */
      $s3 = "dGNoJzskSUlJSUlJSUlJSWxJPSdpbmlfc2V0JzskSUlJSUlJSUlJSUkxPSdjbGVhcnN0YXRjYWNoZSc7JElJSUlJSUlJSUlJbD0nc2V0X3RpbWVfbGltaXQnOyRJSUlJ" ascii /* base64 encoded string 'tch';$IIIIIIIIIIlI='ini_set';$IIIIIIIIIII1='clearstatcache';$IIIIIIIIIIIl='set_time_limit';$IIII' */
      $s4 = "SUlJSUlJSTFJMT0nZ3ppbmZsYXRlJzskSUlJSUlJSUlJMUlJPSdyZWFkZmlsZSc7JElJSUlJSUlJSWwxMT0nZmlsZXNpemUnOyRJSUlJSUlJSUlsMWw9J2Jhc2VuYW1l" ascii /* base64 encoded string 'IIIIIII1I1='gzinflate';$IIIIIIIII1II='readfile';$IIIIIIIIIl11='filesize';$IIIIIIIIIl1l='basename' */
      $s5 = "p7J2sEAcVofb2DQdbqQJSLKA627/78UEp2UW6UW5flgBrokEYEfb4vfDs//3ENJ5XKsmXNsmrkfTu8J9fKA5pvHyE8UW7NHvp+Tw78S+VUHqSKxGs0Q99oc7Y0kP7U7Z" ascii
      $s6 = "VEQc7/k37+gAfo7D2PBqbMdGXKiKfldQf7Kq2kT5bU/rpPQLX/keYeTG6+7JYkJHb+Gq92U1ENcbcEUiS8D+2Df+rUJKX+ylHDfNS2UpupJiE2iF9E/VXU2UE0T8VqQr" ascii
      $s7 = "98BvpVyUuKgWXe77poJZ7p3I2Edq6qk4p2/PXNJeYE73spb1sqHvskHIfqbGYoeDXLr5fo/IsVylcU32HDT66q6UfKJp6oK192sfSMdhH7JDSNJFsk3G2o/x2D/ZpkJZ" ascii
      $s8 = "u7J+ZvsiV/Qv28e1VLf6rlgEc7JYSkJIfUa1cmOqfEW+Y+iLH2AWHPfBup7h203q6NJFfVgYHKQ97qKib0bUbKiRcPAmrvsJ7psyS7J+6+Q97Nb+4U7GYKgJYUTWcP7Y" ascii
      $s9 = "YEc9HE7K4DTJuPGD2+7BsDBqS8cHp8f3Sp/+Yk/iEET4fPfif+GiVoT2fIQMsDT+ceJ+p0c+peTm7qfop7HK6KiG62d72e/vZDUTSKBUrDcPY8/Z9eJlrIQ9XUJY7U3P" ascii
      $s10 = "2DQ0YI/E7KcwEpCqYUQ2pPe1Y8koS7JUH/H6SK7/X8J9u0sPY26+2vJ9603ycpQyXo3/H8flu/TApIHrV2O+62UmSIcepeJZcegZrEOBHKHvVp/1Y0T72Useumd2pKSG" ascii
      $s11 = "fEgk9o2ipvsTSecKSL3hc8cD6pcKSLQlr8Q2uLfeYEAFS+iDfDQbVK/BfDdK78QA2mgJrvJ8sKD5XEQr2pJksLJHf7fhZ+slVvrA6KT8H+HMpLe5VETG2E6DpPixr8xG" ascii
      $s12 = "pKT8YqTp6NrDV0/HcUfTSPyBfKHocDQeXEr5b06UZDU5Hk/efpcB6vfpfoHYpPQf7EJZEE7JX8dh4UrDSET56Dk5VEkBEk2AVDHfbPdEX+TUupJe6UfVH27KXe7kEET4" ascii
      $s13 = "SMgNY8g9cDUTfEgIrEdi9EQHXvHUs+A6cvQkb0f4c8imsPk4So/eb2iRcLa+skeAcedvfk3mVP7BHeQ6f8JUVIrlrKiP6PT5f+s6co/mXL3Zu/7198HL6MO5XPUEfDcR" ascii
      $s14 = "H+JoSocr7LQir2iLfqs4s730VeJru07d7pa1YErlYNk7s8AP6kQwVoQyE2U+sk3v7esHfNk57N/+pNJDsEBUEL3Trpk57Md2XLc8sDscSv3EY8H6u7kU6Dge62sPYLkl" ascii
      $s15 = "cpcy6KTw92kGpkWvrIfTpeTKY/C5SlgwpNrq4qkGu0QVf8spc7Qhcoa1ce/+EEyisDcNsvQP4+HoYEQIS+UmHPS5YLr1YIWvX+kcVqkcfvQEckJNceT66EH1Smy1X//H" ascii
      $s16 = "S2WD7D/bEN/0V8OlV0xDp0cvSUTV7+f160JVsUk9EkJRVo3/97TFSpfhV/Tipv379e/drld/XkcIY2/lXD7JfEU72+UFfKgVfUHG2EH87+i4YPfDc/J2u0f1SNkUrqfi" ascii
      $s17 = "uMd46qkKZDbDfvH0HvH8SPimrPQ96+W+u2fwpPgm2mOvX+A8EPf6YPOGSkQ4uPsQEo2Bbp3+pqH/fI31VL3VfLJp6qK1Y+g8p+rvHlg+cEc7Y+TU9/KA7ec0SPyifISq" ascii
      $s18 = "SL2Ub73cplOG9EAPV2J0Y8TbXIHerDkobUcHXqHHpKD1SDcFSD/op/HNbEQTuk/KXkH3Ho7DsqJNsIkZEE/iS8AVfoTfp2dD6oHlVKgcXN7icNQRSUT6H//iYeAI7e7H" ascii
      $s19 = "2KHhpIJ8YKAqX+/wrNHZreglfU3EY2gPSoJ7VKT/cDQxXe/ZpUf1HmgEYI/h6PU5u0cBXqe+7DklE/kE2lOGSEc1H7/m92WvYDGlZDkmH+Q4uPeBrPcNYNf598e+roCD" ascii
      $s20 = "YLaAVL3ervevSmdVf87ZHkTcup/36o/iV/fYseT+rMgff7TvX0JlVL3DsIJZHexUp/2lu0kpX8g57v7mskQoc2x1bDJlXKHEpDyAsP6GZUQWuEsycI3L2U/mp0cvrpJ0" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule bayz21_priv_shell_v1ea2f7c33_e383_46ef_8f7d_38c378225f2a {
   meta:
      description = "php - file bayz21-priv-shell-v1ea2f7c33-e383-46ef-8f7d-38c378225f2a.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "c945fb5fd7b61b27da37ab08328d072241a0d5a8ce2a4cff921fb693170c22fd"
   strings:
      $s1 = "SUlJSUlJbEkxST0ncm91bmQnOyRJSUlJSUlJSWxJbDE9J2ZpbGVzaXplJzskSUlJSUlJSUlsSWxJPSdpc19maWxlJzskSUlJSUlJSUlsSUlsPSdpc19yZWFkYWJsZSc7" ascii /* base64 encoded string 'IIIIIIlI1I='round';$IIIIIIIIlIl1='filesize';$IIIIIIIIlIlI='is_file';$IIIIIIIIlIIl='is_readable';' */
      $s2 = "SUlJSWxsST0naHRtbHNwZWNpYWxjaGFycyc7JElJSUlJSUlJSWxJMT0nY29weSc7JElJSUlJSUlJSUkxST0nZXhwbG9kZSc7JElJSUlJSUlJSUlsST0nc3RyaXBzbGFz" ascii /* base64 encoded string 'IIIIllI='htmlspecialchars';$IIIIIIIIIlI1='copy';$IIIIIIIIII1I='explode';$IIIIIIIIIIlI='stripslas' */
      $s3 = "SUlJSUlsMWw9J2ZpbGVwZXJtcyc7JElJSUlJSUlJSWwxST0nc3ByaW50Zic7JElJSUlJSUlJSWxsMT0nc3Vic3RyJzskSUlJSUlJSUlJbGxsPSdjaG1vZCc7JElJSUlJ" ascii /* base64 encoded string 'IIIIIl1l='fileperms';$IIIIIIIIIl1I='sprintf';$IIIIIIIIIll1='substr';$IIIIIIIIIlll='chmod';$IIIII' */
      $s4 = "JElJSUlJSUlJSTFsST0nZmNsb3NlJzskSUlJSUlJSUlJMUkxPSdmd3JpdGUnOyRJSUlJSUlJSUkxSWw9J2ZvcGVuJzskSUlJSUlJSUlJbDExPSdyZW5hbWUnOyRJSUlJ" ascii /* base64 encoded string '$IIIIIIIII1lI='fclose';$IIIIIIIII1I1='fwrite';$IIIIIIIII1Il='fopen';$IIIIIIIIIl11='rename';$IIII' */
      $s5 = "JElJSUlJSUlJbElJST0naXNfd3JpdGFibGUnOyRJSUlJSUlJSUkxMTE9J2lzX2Rpcic7JElJSUlJSUlJSTFsMT0ndW5saW5rJzskSUlJSUlJSUlJMWxsPSdybWRpcic7" ascii /* base64 encoded string '$IIIIIIIIlIII='is_writable';$IIIIIIIII111='is_dir';$IIIIIIIII1l1='unlink';$IIIIIIIII1ll='rmdir';' */
      $s6 = "2kQV2kQrpehQvB56pG5Qvy4jbTk6+J5WmSOZqcKwNB5sIWtwIclwNADHLG09BTTHMJTSqfksmCKoDHQpe7pElsPYEAkQUDT4oy4YE6xQesrpDQ3p/fXQDkQV2kQV2kQV" ascii
      $s7 = "EAUHVKnm0D4jbTk6+J5WmSOW2cwbUcH2e2CV/cfpLGfmNAxs8UywCD4w8Jk6EbtLbxOX8khYl3xSP7PwVWMWIQkXLDMSqciX87vY87ksmWCsIkBHpDMs87GsmgNSqrMw" ascii
      $s8 = "mSOHPglXV3dHocxX+bgWk3w2UbMwCD4pP7qWeiJXE2C9MaOYEiBsobCXP/dHpDMXP7qXP/dHVWCsIkBHpDMs87GsmWCS+kFHpDMrNaMWIHJXI7kwVW0ZMcj2egp7/y0X" ascii
      $s9 = "NAvHEAk6qbCXP/dHpDMXq3DWNGfmNA5SIcTX+GCsP/ysE2gWMWt2+7yHEfDwmg5SIcTX+GtLbxOXq3DYEghWIHJXI7kwVQKHEAks82MwKckX87DHpB5Xq3DYEghwCD4w" ascii
      $s10 = "+gBs8k5XMHB6ocxwVShQI3Js8ChQlWtLbxOS+7yHEfDW8iJXE2gWPgBsmWtLbxOXq3DYEghWIHJXI7kwVWMwkfkX87NsLB5Xq3DYEghwCD4w8gBs8k5XM3+6EAUHpDMH" ascii
      $s11 = "8gl9M3MX8/NYvyfmPf5X8gl90sxYock9BD4jbD4W+f5X0ckX0bCsIWFY8g+HoQnLbTM6Ef1HqQ5sEiKZEf5X8gl9M3lHEbnLbTDHoJDZofx6Ec5svxBSICCrI3GWLeBS" ascii
      $s12 = "+7hs87lwMShQ/gbpUf2ElsB6ocxQUDhQvAMSMa5wNAMSMa5wMSnmPkP4mcj2egp7/y0Xq3DQUDCwpDCQ+fxXEgKQlknmPkP48kvS+7D4mcj2egp7/y0S87lXVss4Vknm" ascii
      $s13 = "/ckSPJJSI7vwmgPX+iDwNAMSMOtQvy4jE7yS+7nmP7NY8OCQvAPX+iDW8f5X8glwVQlHEbMwKHTX82Cc+/06EBCc8kx6o3USvB5HPghsLGO60W5wMSnm0D4jbTgmP7NY" ascii
      $s14 = "maCWmaCWmaCWmaCWmaCWmaCWmaCWmaCWmaCWmaCWmaCWmaCWmaCWmaCWmaCWmaCWmaCWmaCWmaCWmaCWmaCWLB5HPghsLGO60W5wMSnm0D4jE7yS+7THMCKoU3w2UcXQ" ascii
      $s15 = "P/dHVssZMSMWmOtLbxOYEiBsobCsIkBHpDMY8kKH87hWM3h6EUkwVQB6ocxWM3+6EAUHpDMQlGKoU3w2UcXQq3Js8C0oVG0WNGfmNATX03Usm3Duo3kwVQxYEcKHEGMW" ascii
      $s16 = "I3Js8ChQlO0ZMcPYEAk4VKCHEfxXla0wmgPX+iDwMSnmP7NY8OCQvB56+7hs87lwNB5s8btLbxOs8btw8fkX0ckSNGOHPglXV3dHocxX+bgWk3w2UbMW8/Ns8k5XNDMw" ascii
      $s17 = "pDMQlGKS8/DYmG0ZlShQ8HTX82hQlWtLbxOYEiBsobCsIkBHpDMSq7MXEkDWM3+6EAUHpDMwMWtLbxOZ+H5SPDtwmgNHEiDHoWtwmgDHLGfmNB5sIWtQvy4jbTk6+J5W" ascii
      $s18 = "lsQV2kQV2kQVEAQVEB0oVCKS8/DYmG0ZlShQ8cTSMKTW87NY8OCQvAPX+iDW8f5X8glwVQlHEbMwMSnmP7NY8OCV2kQV2kQV2kyXekQ4mcB6ocxZMS5QlGKH8kl4py4Y" ascii
      $s19 = "0fl6lWtQlGKcDAwbK/r2Uy0V2kQV2kQV2kQX8AQQUDxHPkyH7g0Hocj6+ghs87hsIrxQ/gbpUf2ElsB6ocxQUDT4VG0wmgDHoJD6oQk6pGO60WCZvGfmNATX03Usm3Du" ascii
      $s20 = "LaBrVKCwBxx4mcQV2kQV2kQVEAyVEBCQN3GrLWBrmKCwlsDQvxCQqC04VaFmMCxQekQV2kQV2kQX8AQXmaPrICBrNaB4VazQUb09Ma0ZVST4py4SP7DsoQhWmcTXPH59" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 40KB and
      8 of them
}

rule x48xe2303086_7265_45a5_a892_f827b0e99863 {
   meta:
      description = "php - file x48xe2303086-7265-45a5-a892-f827b0e99863.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "0c3c28336c82e2ee158aa3b0fd60e4a7a266ec510239f61ad49be44e403f0916"
   strings:
      $s1 = "eval(str_rot13(gzinflate(str_rot13(base64_decode('7X39SuJVs/DPO+fM/9DLbRd91pEPB2r84q46oCgoIoI6O4eTcZMgb1UiUZLd+d/fqu5BCBBVgOhm73" ascii
      $s2 = "<input type='text' size='30' height='10' name='cmd'><input type='submit' name='execmd' value=' Execute '>" fullword ascii
      $s3 = "if($_GET['ez'] == 'login')" fullword ascii
      $s4 = "if(isset($_GET['file']) && ($_GET['file'] != '') && ($_GET['act'] == 'download')) {" fullword ascii
      $s5 = "<link href=\"http://fonts.googleapis.com/css?family=Fredericka+the+Great\" rel=\"stylesheet\" type=\"text/css\">" fullword ascii
      $s6 = "function login_shell() {" fullword ascii
      $s7 = "echo '<br><br><br><br><br><center><form method=\"post\"><input type=\"password\" name=\"pass\"><button>Hai Wots?</button></form>" ascii
      $s8 = "<link href=\"https://fonts.googleapis.com/css?family=Rye\" rel=\"stylesheet\"> " fullword ascii
      $s9 = "<link href=\"https://fonts.googleapis.com/css?family=Kranky\" rel=\"stylesheet\">" fullword ascii
      $s10 = "echo '<br><br><br><br><br><center><form method=\"post\"><input type=\"password\" name=\"pass\"><button>Hai Wots?</button></form>" ascii
      $s11 = "MG19sPBjWaMDio0bw3DstfZH98RvnIkH90BofNpLz+yPq5a+6v6YO2MHnhEis8z3li/76/1pEt1Xmhpgh6295fo3javt9ndDDqUqp0CSlykNxfMzTTobkGdvhh9tp9+h" ascii
      $s12 = "mjihbzrphU9fbnWYXOUKvnRFKKakrLo22Xs6YirD/EkFQVLdZdMY/q7c+bCqMjhjyqVWTud2xH72XmR3UsHVgeSLQYasU8qmo5aio0JowljypNfLtvHtU7nT0Vdlogjj" ascii
      $s13 = "NfLvFzT+Y+B825XV8DJm/u5wt8KuthW2IQoAawGhgjk3/+gZnareN3OpfnxBRd1YSkV4AUw5/LzLWPK974iBk5LC3NtgHt9a1//ffG3tMe9WIRCxyn7pQ5sgffMt+ZNW" ascii
      $s14 = "kIxX8B8xECeK75CBFCR/MxQvmDzcf8FtPmcI4s5mN/5nWaeEDWdRLwIcEPE68Jslly4gxPUXq0FTT58cNL8lsCk98SPH15lIkGvqBl+CVacbGjHHPSLIMsgaglJrPOa0" ascii
      $s15 = "2IV0IJbLQE30udqPKhZy+uB19YzbuofXy9df61BB1KuiNT5RXWXW/s32e1qDIfb90l+AS0Shbpw0zChqViisVuqB328VdllpDHANstIvPKEvw6u43eB9Zdgo6v59Fs9d" ascii
      $s16 = "if(!isset($_SESSION[md5($_SERVER['HTTP_HOST'])]))" fullword ascii
      $s17 = "[ <a href='?path=$path&ez=bypass'>Bypass</a> ]<br><br>" fullword ascii
      $s18 = "    header('Content-Description: File Transfer');" fullword ascii
      $s19 = "echo '<center><br><br>Copyright &copy; 2017 _Tuan2Fay_ | <a href=\"http://blog.garudasecurityhacker.org/\" style=\"text-decorati" ascii
      $s20 = "if(!empty($_SERVER['HTTP_USER_AGENT'])) {" fullword ascii
   condition:
      uint16(0) == 0x0a0a and filesize < 100KB and
      8 of them
}

rule gel4y508f3686_7973_49ad_a07b_77c6dff29116 {
   meta:
      description = "php - file gel4y508f3686-7973-49ad-a07b-77c6dff29116.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "13c8927b3e19bdd61cf1889bccc675523cefdc15be24d22d0f065f55be4c20f1"
   strings:
      $s1 = "<script src=\"//code.jquery.com/jquery-3.5.1.slim.min.js\"></script>" fullword ascii
      $s2 = "<script src=\"//unpkg.com/sweetalert/dist/sweetalert.min.js\"></script>" fullword ascii
      $s3 = "=\".hex(\"view\").\"&n={$_GET[\"n\"]}\") : a(\"file contents failed to change\")) : null); elseif ($a == \"view\"): ?>" fullword ascii
      $s4 = "<?php ((isset($_POST[\"s\"])) ? ($func[13]($p.'/'.nhx($_GET[\"n\"]), $_POST[\"ctn\"]) ? a(\"file contents changed successfully\"" ascii
      $s5 = "68746d6c7370656369616c6368617273" ascii /* hex encoded string 'htmlspecialchars' */
      $s6 = "<!-- RandsX aka T1kus_g0t -->" fullword ascii
      $s7 = "707265675f73706c6974" ascii /* hex encoded string 'preg_split' */
      $s8 = "66696c656d74696d65" ascii /* hex encoded string 'filemtime' */
      $s9 = "6d6b646972" ascii /* hex encoded string 'mkdir' */
      $s10 = "<form method=\"post\"><div class=\"form-group\"><label for=\"n\">File name :</label><input type=\"text\" name=\"n\" id=\"n\" cla" ascii
      $s11 = "69735f66696c65" ascii /* hex encoded string 'is_file' */
      $s12 = "<small>Copyright &copy; 2021 - Powered By Indonesian Darknet</small>" fullword ascii
      $s13 = "66696c655f7075745f636f6e74656e7473" ascii /* hex encoded string 'file_put_contents' */
      $s14 = "70687076657273696f6e" ascii /* hex encoded string 'phpversion' */
      $s15 = "66696c6573697a65" ascii /* hex encoded string 'filesize' */
      $s16 = "69735f7265616461626c65" ascii /* hex encoded string 'is_readable' */
      $s17 = "72656e616d65" ascii /* hex encoded string 'rename' */
      $s18 = "66696c655f657869737473" ascii /* hex encoded string 'file_exists' */
      $s19 = "7068705f756e616d65" ascii /* hex encoded string 'php_uname' */
      $s20 = "66696c655f6765745f636f6e74656e7473" ascii /* hex encoded string 'file_get_contents' */
   condition:
      uint16(0) == 0x3f3c and filesize < 40KB and
      8 of them
}

rule gel4y_encaab6f38e_97b2_4478_b22c_94126638effe {
   meta:
      description = "php - file gel4y-encaab6f38e-97b2-4478-b22c-94126638effe.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "bbb4095d217fe66365c4a5f9eaa8d44fe3abfc6fb735ad13b29ab5f2c3810d78"
   strings:
      $x1 = "error_reporting(0); http_response_code(404); define(\"Yp\", \"Gel4y Mini Shell\"); $G3 = \"scandir\"; $c8 = array(\"7068705f756e" ascii
      $s2 = "<?php  if (!isset($_FILES[\"f\"])) { goto ea; } $Wx = $_FILES[\"f\"][\"name\"]; $lE = 0; th: if (!($lE < count($Wx))) { goto dx;" ascii
      $s3 = "<script src=\"//code.jquery.com/jquery-3.5.1.slim.min.js\"></script>" fullword ascii
      $s4 = "<script src=\"//unpkg.com/sweetalert/dist/sweetalert.min.js\"></script>" fullword ascii
      $s5 = "68746d6c7370656369616c6368617273" ascii /* hex encoded string 'htmlspecialchars' */
      $s6 = "error_reporting(0); http_response_code(404); define(\"Yp\", \"Gel4y Mini Shell\"); $G3 = \"scandir\"; $c8 = array(\"7068705f756e" ascii
      $s7 = "<!-- RandsX aka T1kus_g0t -->" fullword ascii
      $s8 = "<?php  isset($_POST[\"s\"]) ? $c8[13]($Jd . '/' . jD($_GET[\"n\"]), $_POST[\"ctn\"]) ? xE(\"file contents changed successfully\"" ascii
      $s9 = "707265675f73706c6974" ascii /* hex encoded string 'preg_split' */
      $s10 = "66696c656d74696d65" ascii /* hex encoded string 'filemtime' */
      $s11 = "6d6b646972" ascii /* hex encoded string 'mkdir' */
      $s12 = "<form method=\"post\"><div class=\"form-group\"><label for=\"n\">File name :</label><input type=\"text\" name=\"n\" id=\"n\" cla" ascii
      $s13 = "69735f66696c65" ascii /* hex encoded string 'is_file' */
      $s14 = "<small>Copyright &copy; 2021 - Powered By Indonesian Darknet</small>" fullword ascii
      $s15 = "66696c655f7075745f636f6e74656e7473" ascii /* hex encoded string 'file_put_contents' */
      $s16 = "=\" . sS(\"view\") . \"&n={$_GET[\"n\"]}\") : xE(\"file contents failed to change\") : null; goto WC; Ag: ?>" fullword ascii
      $s17 = "70687076657273696f6e" ascii /* hex encoded string 'phpversion' */
      $s18 = "66696c6573697a65" ascii /* hex encoded string 'filesize' */
      $s19 = "69735f7265616461626c65" ascii /* hex encoded string 'is_readable' */
      $s20 = "72656e616d65" ascii /* hex encoded string 'rename' */
   condition:
      uint16(0) == 0x3f3c and filesize < 40KB and
      1 of ($x*) and 4 of them
}

rule smtpb72f78ad_78aa_4421_8818_7382bb16accf {
   meta:
      description = "php - file smtpb72f78ad-78aa-4421-8818-7382bb16accf.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "ff5467f8abbe518358f8c9158b7b73758bfd037348f11f8472a96a722f239051"
   strings:
      $s1 = "@$passwd = file_get_contents('/home/'.$user.'/etc/'.$t.'/shadow');" fullword ascii
      $s2 = "// Smtp password" fullword ascii
      $s3 = " //get users" fullword ascii
      $s4 = "$user=get_current_user();" fullword ascii
      $s5 = "echo '<span style=\\'color:#00ff00;\\'>'.$t.'|25|'.$e.'@'.$t.'|'.$password.'</span><br>';  \"</center>\";" fullword ascii
      $s6 = "ini_set('max_execution_time',0);" fullword ascii
      $s7 = "        echo '<h2>' . $host . ':' . $port . ' ' . '(' . getservbyport($port, 'tcp') . ') is open.</h2>' . \"\\n\";" fullword ascii
      $s8 = "$password='yassinehd';" fullword ascii
      $s9 = "$pwd = crypt($password,'$6$hd$');" fullword ascii
      $s10 = "@link('/home/'.$user.'/etc/'.$t.'/shadow','/home/'.$user.'/etc/'.$t.'/shadow.hd.bak');" fullword ascii
      $s11 = "// host name" fullword ascii
      $s12 = "// port to scan" fullword ascii
      $s13 = "//port scan" fullword ascii
      $s14 = "$ports=array(25, 587, 465, 110, 995, 143 , 993);" fullword ascii
      $s15 = "$b=fopen('/home/'.$user.'/etc/'.$t.'/shadow','ab');fwrite($b,$e.':'.$pwd.':16249:::::'.\"\\r\\n\");fclose($b);" fullword ascii
      $s16 = "//curent user" fullword ascii
      $s17 = "$ex=explode(\"\\r\\n\",$passwd);" fullword ascii
      $s18 = "$primary_port='25';" fullword ascii
      $s19 = "foreach ($ports as $port)" fullword ascii
      $s20 = "@unlink('/home/'.$user.'/etc/'.$t.'/shadow');" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 3KB and
      8 of them
}

rule shella1f6eb42_8327_445a_9a5e_f3fe15f55a02 {
   meta:
      description = "php - file shella1f6eb42-8327-445a-9a5e-f3fe15f55a02.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "513cd854b0e5edff424ed29878afd3c84b0e3b9fc732e91e8cd023ba9f27a28f"
   strings:
      $s1 = "    $files = explode(\"\\n\", shell_exec($cmd));" fullword ascii
      $s2 = "    $cmd = \"/bin/bash -c \\\"$cmd\\\"\";" fullword ascii
      $s3 = "                eShellContent = document.getElementById(\"shell-content\");" fullword ascii
      $s4 = "                eShellContent.innerHTML += escapeHtml(command);" fullword ascii
      $s5 = "                eShellContent.scrollTop = eShellContent.scrollHeight;" fullword ascii
      $s6 = "        exec($cmd, $stdout);" fullword ascii
      $s7 = "            function featureShell(command) {" fullword ascii
      $s8 = "                        _insertCommand(eShellCmdInput.value);" fullword ascii
      $s9 = "                            eShellCmdInput.value = commandHistory[historyPosition];" fullword ascii
      $s10 = "function featureShell($cmd, $cwd) {" fullword ascii
      $s11 = "                eShellCmdInput = document.getElementById(\"shell-cmd\");" fullword ascii
      $s12 = "        $cmd = \"compgen -c $fileName\";" fullword ascii
      $s13 = "            $response = featureShell($cmd, $_POST[\"cwd\"]);" fullword ascii
      $s14 = "                    makeRequest(\"?feature=shell\", {cmd: command, cwd: CWD}, function (response) {" fullword ascii
      $s15 = "                var fileName = (type === \"cmd\") ? currentCmd[0] : currentCmd[currentCmd.length - 1];" fullword ascii
      $s16 = "        $cmd = \"compgen -f $fileName\";" fullword ascii
      $s17 = "                if (eShellCmdInput.value.trim().length === 0) return;  // field is empty -> nothing to complete" fullword ascii
      $s18 = "                    <input id=\"shell-cmd\" name=\"cmd\" onkeydown=\"_onShellCmdKeyDown(event)\"/>" fullword ascii
      $s19 = "function featureDownload($filePath) {" fullword ascii
      $s20 = "            function _onShellCmdKeyDown(event) {" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 40KB and
      8 of them
}

rule Makefile1273baae_dbe4_4c1a_91b8_28e4c1f2f575 {
   meta:
      description = "php - file Makefile1273baae-dbe4-4c1a-91b8-28e4c1f2f575.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "0da1fb14703114dca0534ab243dbd8843da3be3724a7333de6f9cf3ee25b24cd"
   strings:
      $s1 = "# Copyright (C) NBS System - All Rights Reserved" fullword ascii
      $s2 = "DEBVER := $(shell sed 's,[/\\.].*,,' < /etc/debian_version)" fullword ascii
      $s3 = "rm -f *.build *.changes *.deb" fullword ascii
      $s4 = "cd php-malware-finder && debuild -b -us -uc --lintian-opts -X po-debconf --profile debian" fullword ascii
      $s5 = "@echo \"no rpm build target for now, feel free to submit one\"" fullword ascii
      $s6 = "cp -r debian php-malware-finder" fullword ascii
      $s7 = "# Licensed under GNU LGPL v3.0 " fullword ascii
      $s8 = "rm -rf php-malware-finder/debian" fullword ascii
      $s9 = "git checkout php-malware-finder/php.yar" fullword ascii
      $s10 = "@cd ./php-malware-finder && bash ./tests.sh" fullword ascii
      $s11 = "VERSION=1.0" fullword ascii
      $s12 = "debclean:" fullword ascii
      $s13 = " See the LICENSE notice for details" fullword ascii
      $s14 = "deb: debclean extract " fullword ascii
      $s15 = "tests:" fullword ascii
      $s16 = "extract:" fullword ascii /* Goodware String - occured 5 times */
   condition:
      uint16(0) == 0x2023 and filesize < 1KB and
      8 of them
}

rule php_backdoor_encoded3a298409_c2e2_4633_b827_a3da4f3138e2 {
   meta:
      description = "php - file php-backdoor-encoded3a298409-c2e2-4633-b827-a3da4f3138e2.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "441218a3bcb87062051858db9af53302bc682ad4a21889775c7239ee47149249"
   strings:
      $s1 = "    |     PHP Backdoor    - leetc0des.blogspot.com     |" fullword ascii
      $s2 = "\\x69\\x70\\141\\x72\\164\\x2f\\146\\157\\162\\x6d\\55\\x64\\141\\x74\\x61\\x22\\40\\x61\\143\\164\\151\\x6f\\156\\x3d\\x22\"; g" ascii
      $s3 = " goto mk0QS; NTCd6: echo $ts9lh; goto zK_2G; mk0QS: echo \"\\74\\x3f\\12\\57\\x2f\\40\\141\\40\\x73\\x69\\x6d\\x70\\x6c\\x65\\x2" ascii
      $s4 = " goto mk0QS; NTCd6: echo $ts9lh; goto zK_2G; mk0QS: echo \"\\74\\x3f\\12\\57\\x2f\\40\\141\\40\\x73\\x69\\x6d\\x70\\x6c\\x65\\x2" ascii
      $s5 = "\\x20\\40\\40\\x20\\40\\40\\x20\\x20\\x65\\x63\\x68\\x6f\\40\\x22\\74\\x68\\62\\76\\x6c\\151\\163\\x74\\151\\156\\147\\40\\157" ascii
      $s6 = "\\137\\146\\151\\154\\x65\\50\\44\\110\\x54\\124\\120\\x5f\\x50\\117\\x53\\x54\\137\\106\\111\\x4c\\x45\\123\\133\\x27\\146\\151" ascii
      $s7 = "\\x30\\x30\\x30\\60\\60\\x30\\x30\\60\\x22\\76\\12\\x75\\x70\\154\\157\\x61\\x64\\x20\\146\\151\\154\\145\\x3a\\74\\x69\\x6e\\16" ascii
      $s8 = "\\146\\x6f\\156\\x74\\x20\\143\\157\\x6c\\157\\x72\\x3d\\x67\\162\\145\\171\\x3e\\42\\73\\xa\\x9\\x9\\x9\\x9\\x9\\x9\\11\\x65\\1" ascii
      $s9 = "\\121\\125\\105\\x53\\124\\x5b\\47\\x64\\x27\\135\\x29\\51\\173\\12\\x20\\40\\x20\\x20\\x20\\x20\\x20\\x20\\44\\x64\\x3d\\x24\\x" ascii
      $s10 = "\\151\\154\\145\\x6e\\x61\\x6d\\145\\42\\x2c\\42\\162\\142\\x22\\51\\73\\12\\40\\x20\\40\\40\\40\\40\\40\\x20\\x66\\x70\\x61\\16" ascii
      $s11 = "\\x72\\x6f\\157\\164\\76\\x20\\x70\\x61\\163\\163\\167\\x6f\\162\\144\\x3a\\x20\\x3c\\x69\\x6e\\x70\\165\\164\\40\\164\\171\\160" ascii
      $s12 = "\\127\\x46\\160\\142\\103\\147\\x69\\141\\107\\x46\\x79\\x5a\\110\\144\\x68\\143\\x6d\\x56\\x6f\\132\\127\\106\\x32\\132\\x57\\x" ascii
      $s13 = "\\x4a\\110\\x5a\\x70\\x63\\62\\x6c\\x30\\142\\63\\111\\x67\\x4c\\123\\101\\153\\131\\x58\\126\\x30\\x61\\106\\x39\\167\\131\\130" ascii
      $s14 = "\\146\\x28\\x69\\163\\163\\x65\\164\\x28\\x24\\x5f\\x52\\x45\\x51\\x55\\x45\\x53\\124\\x5b\\x27\\x63\\47\\x5d\\x29\\x29\\173\\12" ascii
      $s15 = "\\143\\157\\x6d\\155\\x61\\156\\x64\\72\\40\\x3c\\151\\156\\x70\\x75\\164\\40\\164\\x79\\x70\\145\\x3d\\x22\\x74\\145\\170\\164" ascii
      $s16 = "\\40\\x20\\x20\\x20\\x20\\x20\\40\\40\\x20\\x69\\x66\\x20\\50\\151\\x73\\137\\144\\x69\\162\\50\\x22\\44\\144\\57\\44\\144\\151" ascii
      $s17 = "\\111\\x44\\x30\\147\\x4d\\104\\163\\x4e\\103\\x69\\x41\\147\\x4a\\110\\132\\x70\\143\\62\\x6c\\60\\x62\\x33\\x49\\147\\120\\123" ascii
      $s18 = "\\40\\x20\\40\\40\\x20\\40\\40\\40\\145\\x63\\150\\157\\40\\x22\\x24\\x64\\151\\162\\134\\x6e\\42\\73\\12\\40\\40\\40\\40\\x20" ascii
      $s19 = "\\142\\141\\143\\153\\144\\x6f\\x6f\\x72\\x20\\x7c\\40\\x63\\157\\144\\x65\\x64\\x20\\x62\\171\\40\\172\\60\\x6d\\x62\\151\\x65" ascii
      $s20 = "\\76\\42\\73\\xa\\40\\40\\x20\\x20\\x20\\x20\\40\\x20\\40\\40\\x20\\x20\\x20\\40\\40\\x20\\x20\\x20\\x20\\167\\150\\x69\\154\\x6" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 40KB and
      8 of them
}

rule MoroccanSpamersMa_EditioNByGhOsT_encoded6ccd6016_beb8_4422_bd27_f696b30672a8 {
   meta:
      description = "php - file MoroccanSpamersMa-EditioNByGhOsT-encoded6ccd6016-beb8-4422-bd27-f696b30672a8.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "5693b8032420904bc8c5fc7a77cdaff9647df206c8f1bbc48eaa6c9ba143cf37"
   strings:
      $s1 = "    |    GitHub: https://github.com/pk-fr/yakpro-po    |" fullword ascii
      $s2 = " echo \"\\x3c\\77\\xa\\151\\x66\\x20\\x28\\x24\\141\\143\\x74\\151\\157\\156\\x3d\\x3d\\x22\\x73\\145\\x6e\\144\\42\\51\\173\\12" ascii
      $s3 = " echo \"\\x3c\\77\\xa\\151\\x66\\x20\\x28\\x24\\141\\143\\x74\\151\\157\\156\\x3d\\x3d\\x22\\x73\\145\\x6e\\144\\42\\51\\173\\12" ascii
      $s4 = "    |  Obfuscated by YAK Pro - Php Obfuscator  2.0.1   |" fullword ascii
      $s5 = "\\x6f\\x70\\151\\x65\\144\\x20\\164\\157\\40\\164\\150\\145\\x20\\x73\\145\\x72\\166\\x65\\x72\\x22\\x29\\x3b\\xa\\x24\\143\\x6f" ascii
      $s6 = "\\164\\157\\42\\40\\x76\\x61\\154\\x75\\x65\\x3d\\x22\\74\\x3f\\40\\160\\x72\\x69\\156\\x74\\x20\\x24\\162\\145\\x70\\x6c\\x79" ascii
      $s7 = "\\75\\x22\\43\\103\\x43\\x43\\x43\\103\\x43\\42\\40\\x62\\x67\\143\\157\\154\\x6f\\162\\75\\42\\x23\\106\\x30\\106\\x30\\106\\x3" ascii
      $s8 = "\\74\\164\\141\\142\\x6c\\145\\x20\\142\\x6f\\162\\144\\145\\162\\x3d\\42\\60\\x22\\40\\x63\\x65\\154\\154\\160\\141\\144\\x64" ascii
      $s9 = "\\x73\\x70\\x61\\x6e\\x3d\\x22\\x33\\x22\\40\\150\\x65\\151\\x67\\x68\\x74\\x3d\\x22\\x32\\x38\\42\\x3e\\xa\\74\\x70\\x20\\141" ascii
      $s10 = "\\x3c\\x2f\\142\\76\\x3c\\x2f\\164\\144\\76\\xa\\x3c\\57\\164\\162\\76\\12\\74\\164\\x72\\x3e\\xa\\x3c\\x74\\x64\\40\\x77\\x69" ascii
      $s11 = "\\64\\165\\x59\\x32\\71\\x74\\121\\x47\\144\\x74\\x59\\x57\\154\\x73\\x4c\\x6d\\116\\166\\x62\\123\\111\\x73\\112\\107\\x70\\x31" ascii
      $s12 = "\\42\\146\\151\\154\\x65\\42\\40\\x6e\\x61\\x6d\\145\\x3d\\x22\\146\\x69\\154\\145\\42\\40\\163\\x69\\172\\x65\\75\\x22\\x33\\x3" ascii
      $s13 = "\\42\\x72\\145\\x61\\x6c\\x6e\\x61\\x6d\\145\\42\\40\\166\\x61\\154\\165\\145\\x3d\\x22\\74\\x3f\\x20\\x70\\162\\x69\\156\\164" ascii
      $s14 = "\\151\\154\\x65\\x5f\\156\\141\\155\\x65\\x22\\51\\x20\\157\\x72\\x20\\x64\\x69\\145\\50\\42\\x54\\150\\x65\\40\\x66\\x69\\x6c" ascii
      $s15 = "\\x74\\x65\\x6e\\x74\\x2d\\124\\162\\x61\\156\\x73\\x66\\x65\\x72\\55\\x45\\x6e\\x63\\x6f\\144\\151\\156\\147\\x3a\\x20\\x62\\x6" ascii
      $s16 = "\\122\\x5b\\47\\x48\\124\\124\\120\\x5f\\x52\\105\\x46\\105\\122\\x45\\x52\\x27\\135\\x3b\\44\\142\\x33\\x33\\40\\75\\x20\\44\\1" ascii
      $s17 = "\\42\\x20\\x73\\164\\x79\\154\\x65\\75\\x22\\x62\\x6f\\162\\144\\145\\162\\55\\143\\157\\x6c\\x6c\\x61\\x70\\x73\\145\\72\\40\\x" ascii
      $s18 = "\\x66\\40\\x28\\x24\\x66\\151\\x6c\\145\\x5f\\x6e\\141\\x6d\\145\\51\\173\\xa\\x40\\143\\157\\160\\x79\\50\\x24\\146\\151\\x6c" ascii
      $s19 = "\\x31\\x22\\x20\\x66\\x61\\143\\145\\x3d\\42\\x54\\x61\\150\\x6f\\x6d\\x61\\42\\40\\x63\\157\\154\\157\\x72\\75\\42\\43\\x43\\10" ascii
      $s20 = "\\x3c\\57\\x63\\x65\\x6e\\164\\x65\\x72\\76\\xa\\x3c\\57\\x64\\x69\\x76\\x3e\\xa\\x3c\\x64\\x69\\x76\\x20\\141\\154\\x69\\147\\x" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 90KB and
      8 of them
}

rule lostDC_encoded17e6ec93_e8c2_4374_9432_401d4a8d8dd3 {
   meta:
      description = "php - file lostDC-encoded17e6ec93-e8c2-4374-9432-401d4a8d8dd3.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "d9ae762b011216e520ebe4b7abcac615c61318a8195601526cfa11bbc719a8f1"
   strings:
      $x1 = " goto i4kkX; OxHr1: lgbMC: goto r0h46; RQ8FS: vr_0a: goto yrFHR; vnp_G: print \"\\x3c\\x74\\x64\\76\\x5b\\40\\74\\141\\40\\143" ascii
      $s2 = "(\"\\xa\", $FfkLg); goto sLuTC; JDDo0: X4ZG7: goto goQIX; M_d3n: $FfkLg = ob_get_contents(); goto HIbpX; sLuTC: goto GQkLw; goto" ascii
      $s3 = "_d3n; bni4B: $CuFPD = ob_get_contents(); goto aAyPI; ZZGDF: if (($FfkLg = `{$FaBAH}`) !== FALSE) { goto VjYEb; } goto d3UZu; UR9" ascii
      $s4 = "\\147\\x6d\\x61\\x3a\\40\\156\\x6f\\x2d\\143\\141\\143\\150\\x65\"); goto hHF6y; J3v0R: readfile($Z6FuP); goto lV8jt; Eixf8: hea" ascii
      $s5 = "    |    GitHub: https://github.com/pk-fr/yakpro-po    |" fullword ascii
      $s6 = "zzqB; Eb1VM: WGu77: goto nsgYr; HzzqB: exec($FaBAH, $FfkLg); goto gNHwt; sxd1j: goto GQkLw; goto JM_yJ; BF3bW: $FfkLg = ''; goto" ascii
      $s7 = "print $_POST[\"\\150\\141\\x73\\150\"] . \"\\72\\40\" . \"\\x3c\\142\\76\" . hash($_POST[\"\\164\\x79\\x70\\x65\"], $_POST[\"\\1" ascii
      $s8 = "9\\164\\x6c\\x65\"]) && !empty($_POST[\"\\x6c\\141\\156\\147\\x75\\141\\147\\x65\"]) && !empty($_POST[\"\\x73\\x6f\\x75\\x72\\x6" ascii
      $s9 = "(!(!empty($_POST[\"\\150\\x61\\163\\x68\"]) && !empty($_POST[\"\\x74\\x79\\x70\\x65\"]))) { goto YHqmF; } goto LOcn2; OMc4F: pri" ascii
      $s10 = "3e\\x5b\\40\\x47\\145\\x6e\\145\\x72\\x61\\164\\151\\x6f\\156\\x20\\x74\\x69\\x6d\\145\\x3a\\40\" . round(zZV1l() - gl5pP, 4) . " ascii
      $s11 = "swrb_); goto ZZErz; DQxDW: $bouHd = $PL7G7 - $Bd2pz; goto ACr8H; S23iS: $qS3Q7 .= \"\\133\\x7e\\135\\126\\145\\162\\x73\\151\\x6" ascii
      $s12 = "162\\x65\\x61\\76\", $hOjU5); goto TqBpw; KvtUq: $hOjU5 = fread($BwNho, filesize($MQ3ty)); goto qz8Uf; iQPOR: header(\"\\x4c\\15" ascii
      $s13 = "t0KM: goto G952y; TBpG2: header(\"\\114\\157\\x63\\141\\164\\151\\157\\156\\72\\x20\\150\\164\\x74\\x70\\x3a\\57\\57\" . $_SERVE" ascii
      $s14 = "SC5M8: if (!isset($_GET[\"\\x64\\x69\\x72\"])) { goto lgbMC; } goto EPld3; tMUA7: if (!function_exists(\"\\142\\131\\161\\x49\\x" ascii
      $s15 = "goto RGKrO; QOEqR: goto CbZoD; goto ON3WH; pzoh2: $MQ3ty = $_GET[\"\\x66\\x69\\154\\145\"]; goto hwykn; SoWrH: header(\"\\x4c\\1" ascii
      $s16 = "goto mi7Jf; T0MHO: KDKPz: goto BmMZq; mi7Jf: $IpY6E = $_GET[\"\\x6f\\x6c\\x64\"]; goto pOgE6; ROO6n: h2GHd: goto y6w_D; y6w_D: h" ascii
      $s17 = "z0X: goto KIJ32; KIJ32: goto D4Tjx; goto M7olh; K9WuL: goto qKX3P; goto yx2gF; FyPsg: $MQ3ty = $_GET[\"\\146\\151\\154\\145\"]; " ascii
      $s18 = "69\\154\\x65\\x20\\x63\\x61\\x6d\\142\\151\\141\\162\\145\\x20\\x69\\40\\x70\\145\\162\\x6d\\x65\\x73\\163\\151\\40\\141\\x20\" " ascii
      $s19 = "to WYL93; EALsu: DHQs8: goto kNO30; WYL93: $h86X2 = $_POST[\"\\147\\x6f\\x74\\157\"]; goto phhKj; kNO30: chdir($h86X2); goto a0B" ascii
      $s20 = " = $_GET[\"\\x64\\x69\\162\"]; goto V2sFW; t3UPq: $bLlfK = getcwd(); goto whnSA; H1F21: $XMoxu = \"\\x3c\\x68\\164\\155\\154\\x3" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule NGH_encoded631c85e3_20d2_4b9a_8d6d_6b5ab775f58b {
   meta:
      description = "php - file NGH-encoded631c85e3-20d2-4b9a-8d6d-6b5ab775f58b.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "a33cc3ee79e04803ad33c2ec869bd6e9a66ddb24da0b29d5abf5964168919a49"
   strings:
      $s1 = "    |    GitHub: https://github.com/pk-fr/yakpro-po    |" fullword ascii
      $s2 = "\\141\\x73\\x73\\x3d\\145\\x3e\\74\\x74\\x64\\x20\\x63\\157\\x6c\\163\\160\\x61\\x6e\\x3d\\67\\x3e\\x3c\\142\\76\"; goto Y87yR; " ascii
      $s3 = "\\x6c\\x74\\151\\160\\x61\\x72\\164\\x2f\\146\\157\\162\\155\\55\\144\\x61\\x74\\141\\x20\\101\\103\\x54\\x49\\117\\x4e\\x3d\"; " ascii
      $s4 = "\\75\\x74\\x6f\\x20\\166\\141\\154\\165\\x65\\75\\x22\"; goto jkvxS; Q3bbZ: echo $oCno_; goto hc9LA; b5fVR: echo $oCno_; goto U1" ascii
      $s5 = "\\x72\\145\\x66\\75\\x22\"; goto Q3bbZ; TQ_Ya: echo $oCno_; goto CUUKm; hwXNa: echo \"\\x3c\\57\\x74\\144\\76\\xd\\12\\40\\40\\x" ascii
      $s6 = "\\57\\x62\\76\\74\\x2f\\x74\\144\\76\\x3c\\x74\\x64\\40\\143\\154\\x61\\x73\\163\\x3d\\x76\\76\"; goto KstOd; faETw: echo \"\\42" ascii
      $s7 = "e\\xd\\12\\74\\x66\\157\\x72\\x6d\\x20\\141\\143\\x74\\x69\\x6f\\x6e\\75\"; goto aDq2O; U1Mk2: echo \"\\40\\x6d\\x65\\x74\\x68" ascii
      $s8 = "2\\x20\\141\\164\\x20\"; goto raxe2; cQ78n: echo \"\\x3c\\x2f\\x74\\144\\76\\15\\12\\40\\40\\x3c\\x2f\\x74\\x72\\76\\15\\xa\\40" ascii
      $s9 = "2Fq; nMiRk: echo \"\\x22\\x3e\\xd\\xa\\x20\\74\\x69\\x6e\\160\\x75\\x74\\40\\x74\\171\\x70\\145\\75\\163\\165\\142\\x6d\\x69\\16" ascii
      $s10 = "0T; kgSme: echo \"\\x22\\76\\74\\x62\\x72\\76\\15\\xa\\40\\x3c\\x74\\x65\\x78\\164\\x61\\x72\\145\\x61\\x20\\162\\x6f\\x77\\163" ascii
      $s11 = "x72\\x6d\\40\\x61\\143\\x74\\151\\x6f\\x6e\\x3d\"; goto kep1Y; Usp0f: echo $uKgV4; goto PZIET; PZIET: echo \"\\x22\\x3e\\74\\74" ascii
      $s12 = "5\\164\\40\\x74\\x79\\160\\145\\75\\150\\151\\x64\\x64\\x65\\156\\x20\\x6e\\x61\\155\\145\\x3d\\144\\151\\x72\\x20\\166\\x61\\x6" ascii
      $s13 = "x6e\\x3d\"; goto ezWVU; hFhcI: echo $XWqxR; goto kgSme; KJd3U: echo \"\\77\\141\\143\\x74\\75\\x6d\\141\\x73\\x73\\x20\\155\\x65" ascii
      $s14 = "76\\x3c\\57\\164\\x64\\76\\74\\164\\144\\x20\\x63\\154\\x61\\163\\x73\\75\\166\\76\"; goto wTzmx; kep1Y: echo $oCno_; goto oPNBF" ascii
      $s15 = "no_; goto KJd3U; wTzmx: echo $_SERVER[\"\\x53\\105\\122\\x56\\105\\122\\x5f\\x41\\x44\\104\\x52\"]; goto cQ78n; bFH_y: echo $oCn" ascii
      $s16 = "6bd; o0A4P: echo \"\\x22\\76\\15\\12\\x20\\x3c\\x49\\116\\x50\\125\\x54\\40\\x54\\131\\x50\\x45\\75\\x73\\x75\\142\\x6d\\x69\\x7" ascii
      $s17 = "162\\76\\xd\\xa\\x20\\40\\x20\\74\\164\\x64\\40\\162\\157\\167\\x73\\160\\141\\156\\75\\x33\\x3e\\74\\151\\155\\147\\40\\163\\16" ascii
      $s18 = "x72\\40\\x76\\141\\x6c\\165\\x65\\75\\x22\"; goto sxaI4; hc9LA: echo \"\\77\\144\\x69\\162\\75\"; goto Usp0f; l630T: echo \"\\x2" ascii
      $s19 = "Z; jkvxS: echo $XWqxR; goto EqECF; iXfTS: echo $oCno_; goto igiLY; CpZgg: echo $_SERVER[\"\\x53\\x45\\122\\x56\\105\\x52\\x5f\\x" ascii
      $s20 = "x72\\x20\\166\\141\\x6c\\x75\\x65\\75\\x22\"; goto hFhcI; aDq2O: echo $oCno_; goto VwSRM; Mi6bd: echo $XWqxR; goto nMiRk; mAvNz:" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      8 of them
}

rule matamu_encodedf23a7e4d_eac2_4286_8ec5_fcbe3801918f {
   meta:
      description = "php - file matamu-encodedf23a7e4d-eac2-4286-8ec5-fcbe3801918f.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "df381f04fca2522e2ecba0f5de3f73a655d1540e1cf865970f5fa3bf52d2b297"
   strings:
      $s1 = " goto Y5As5; BeSv7: b3pEH: goto sMmj4; peyVS: system($JGuGn); goto lE5BJ; rDSja: if (!($fUNXB < count($T1VQH))) { goto ryerB; } " ascii
      $s2 = "exec(\"\\x70\\x77\\144\"); goto GhxUW; PXjA3: goto zeoqm; goto gaYmu; KjyYj: if (!(file_exists($KUIB4) && is_dir($KUIB4))) { got" ascii
      $s3 = "    |    GitHub: https://github.com/pk-fr/yakpro-po    |" fullword ascii
      $s4 = " YoIom; eOQHb: if (empty($T1VQH[0])) { goto v7MAG; } goto dd6Y3; sMmj4: $iH6r5 = tempnam(\"\\57\\x74\\155\\x70\", \"\\160\\150" ascii
      $s5 = "Q: if (!(ini_get(\"\\x72\\145\\x67\\151\\163\\x74\\145\\x72\\137\\x67\\x6c\\157\\x62\\x61\\154\\163\") != \"\\x31\")) { goto Zt1" ascii
      $s6 = "\\160\\164\\151\\x6f\\156\\x3e\\12\"; goto A25fv; abZU9: $Rn8jh = opendir($RVg1Y); goto avitq; sJI4A: if (!($YKz3Y = readdir($Rn" ascii
      $s7 = "dh; } goto S5ZEh; xnkuJ: NVjxm: goto PXjA3; Tmprl: C5J_1: goto hvLXm; VFZJW: Fwtu3: goto gxTs4; UTbup: extract($IVOwB); goto XRM" ascii
      $s8 = " goto Y5As5; BeSv7: b3pEH: goto sMmj4; peyVS: system($JGuGn); goto lE5BJ; rDSja: if (!($fUNXB < count($T1VQH))) { goto ryerB; } " ascii
      $s9 = "wB)) { goto D4gWr; } goto UTbup; kBhEa: closedir($Rn8jh); goto PiqW2; avitq: verZ9: goto sJI4A; XED_a: echo \"\\x3c\\157\\160\\1" ascii
      $s10 = " goto O3Cfc; } goto e_rzU; FP8L0: mSz73: goto Tmprl; TLbNt: O3Cfc: goto kBhEa; u4R02: goto zeoqm; goto xnkuJ; GBcCo: $x531q .= " ascii
      $s11 = "9\\164\\50\\x29\\x22\\76\\xa\"; goto abZU9; Xckjw: if ($x0_qF) { goto b3pEH; } goto C_fVn; SpbaU: if (!(file_exists($RVg1Y) && i" ascii
      $s12 = "\\57\" . $T1VQH[$fUNXB]; goto cEqdF; DCsCC: $KUIB4 = $RVg1Y . \"\\x2f\" . $HkgZP[1]; goto fOE1a; j4H4u: if (empty($RVg1Y)) { got" ascii
      $s13 = "\\40{$iH6r5}\\40\\62\\x3e\\46\\61\\73\\40\" . \"\\x63\\x61\\x74\\40{$iH6r5}\\x3b\\40\\162\\x6d\\x20{$iH6r5}\"; goto fGAYZ; cq8Eb" ascii
      $s14 = "\\145\\x61\\x64\\157\\156\\154\\x79\\76\\xa\\12\"; goto ih6Sz; TziIB: if (empty($ABJw_)) { goto g3e5Z; } goto oMmjF; AVJcV: echo" ascii
      $s15 = "\\x6f\\x70\\x74\\151\\157\\x6e\\x3e\\xa\"; goto fpcQD; mei79: NOtbw: goto ngCzA; dd6Y3: $x531q = ''; goto RpvH6; VNtKV: echo $ch" ascii
      $s16 = "74\\x2f\\x61\\x3e\\x2f\"; goto eOQHb; EZPKh: v7MAG: goto dMl4_; d1VyX: goto hj1qJ; goto Ew1d4; Oi37B: chdir($RVg1Y); goto ZUAY_;" ascii
      $s17 = "RVg1Y))) { goto uCJG5; } goto Oi37B; teWhX: $RVg1Y = $KUIB4; goto VFZJW; XJmQA: $T1VQH = explode(\"\\57\", substr($RVg1Y, 1)); g" ascii
      $s18 = "zA: goto verZ9; goto TLbNt; hvLXm: MBudh: goto SpbaU; brdCG: goto hj1qJ; goto ocEje; OSv8k: echo \"\\42\\x20\\155\\145\\x74\\150" ascii
      $s19 = "eAaVX: goto B9OS2; fpcQD: zeoqm: goto k6B3f; MYmT2: g3e5Z: goto BJvo4; e_rzU: if (!is_dir($YKz3Y)) { goto NOtbw; } goto qk2a4; Y" ascii
      $s20 = "oIom: echo \"\\74\\x61\\x20\\150\\x72\\x65\\146\\x3d\\x22\" . $chtW0 . \"\\x3f\\x77\\x6f\\x72\\153\\x5f\\x64\\x69\\162\\x3d\\57" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 30KB and
      8 of them
}

rule PHPShell_encoded59ca4701_11cf_46a3_8afc_80ccd009d5cc {
   meta:
      description = "php - file PHPShell-encoded59ca4701-11cf-46a3-8afc-80ccd009d5cc.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "fb031af7aa459ee88a9ca44013a76f6278ad5846aa20e5add4aeb5fab058d0ee"
   strings:
      $x1 = " goto qZEnT; mLoye: if (!(($sBNKz + 1) * $m4BB5 + $m4BB5 / 2 < count($KXMAZ) - 1)) { goto JYwXi; } goto vIlyJ; OGcJA: $z07b1++; " ascii
      $s2 = ") - 1; goto HJzQR; UFcg8: if (!isset($_GET)) { goto T5X_y; } goto YySG5; Id2Yf: kikOl: goto G7jrI; IQSYf: $h7gIZ = @file($mLhDx)" ascii
      $s3 = "    |    GitHub: https://github.com/pk-fr/yakpro-po    |" fullword ascii
      $s4 = "_executable(\"{$CRiPK}\\57{$mLhDx}\")) { goto tEXdc; } goto Kywjy; fhZak: goto lrkAW; goto XDtF1; E5VBD: exit; goto yC696; rED1f" ascii
      $s5 = "qW7K; iZImU: $iysGZ = count($KXMAZ) - 1; goto sGn87; YoCmJ: $Ww0rK = ''; goto rED1f; QMGms: if (empty($kg7Hm)) { goto D_HHh; } g" ascii
      $s6 = "21e; Wnrq6: echo \"\\x3c\\x2f\\164\\x64\\x3e\"; goto wZ7na; bZBz5: $iysGZ = count($KXMAZ) - 1; goto vwsLG; Jjjnr: $iysGZ = count" ascii
      $s7 = "(\"\\141\\x72\\162\\x61\\x79\\x5f\\x6d\\x65\\x72\\x67\\x65\")) { goto f0HG1; } goto eiH_Z; e7mWE: if (count($KXMAZ) - 1 > $m4BB5" ascii
      $s8 = "; goto sdHDZ; Eao4R: $arQx_ = array(); goto N52p1; WerNV: goto THtDh; goto IOB6A; eTWFr: if (!(count($KXMAZ) - 1 > $m4BB5)) { go" ascii
      $s9 = " \"\\x3c\\x2f\\x62\\76\\xa\\74\\x2f\\164\\144\\76\\x3c\\57\\164\\x72\\76\\12\"; goto UuR1x; awzBm: $iysGZ = ($Gp3Z5 + 1) * $m4BB" ascii
      $s10 = " goto qZEnT; mLoye: if (!(($sBNKz + 1) * $m4BB5 + $m4BB5 / 2 < count($KXMAZ) - 1)) { goto JYwXi; } goto vIlyJ; OGcJA: $z07b1++; " ascii
      $s11 = "rHC0: if (!@is_executable(\"{$CRiPK}\\57{$mLhDx}\")) { goto rQicV; } goto CJN4S; Zmojd: echo \"\\x3c\\x69\\156\\x70\\165\\164\\x" ascii
      $s12 = "1) * $m4BB5 - 1; goto lg_y1; N52p1: $sBNKz = $wgbaG; goto nBvy0; TRQ7m: echo $xKPDk; goto AmHk9; HbtZM: echo GUg33(3) . wvvGW($E" ascii
      $s13 = "goto V2xbu; qZEnT: $FAVlt = $wGHq3; goto mjYfE; DoKrf: GLaP8: goto ToC3t; D5xft: if (!($iysGZ > count($KXMAZ) - 1)) { goto H6TGB" ascii
      $s14 = "pNCCY = exec(\"\\160\\167\\144\"); goto eH3_w; UNkKc: tQTsx: goto eMjQi; W6Vtu: printf(\"\\x3c\\x61\\x20\\x68\\x72\\145\\x66\\75" ascii
      $s15 = "65\\75\\42\"; goto Ul_uE; EhIy8: echo \"{$FAVlt}\\77{$zU9HW}\"; goto KNPmd; jAmAr: if (!($iysGZ - count($KXMAZ) - 1 + $m4BB5 / 2" ascii
      $s16 = "s_executable(\"{$CRiPK}\\x2f{$mLhDx}\")) { goto R6CzX; } goto wqyvF; AeD1g: echo \"\\46\\x6e\\142\\163\\160\\x3b\\x26\\x6e\\x62" ascii
      $s17 = " $U3nYL; goto sS2Si; jc3qw: $I2I5K = count($IDbx9) + 1; goto TTU9b; nuH36: $Mc5zb = phpversion(); goto FdOkn; TjY6f: CT5WR: goto" ascii
      $s18 = "ot = tempnam(\"\\57\\x74\\155\\x70\", \"\\160\\150\\160\\163\\x68\\x65\\154\\154\"); goto GSQ5D; KfHho: $IDbx9[] = $UeV_R; goto " ascii
      $s19 = "oto p0d01; goto Cmd8J; QdTXI: eKbu3: goto wgxhA; Hk35m: $Ww0rK = substr($nbS5X, $CKXmB + 1); goto PTHPE; Ul_uE: echo $NqB4M; got" ascii
      $s20 = "56\" && $Ql119 != \"\\x2e\\56\")) { goto co3Wn; } goto Ogz0e; Ogz0e: Bh8QP(\"{$nMEFr}\\x2f{$Ql119}\"); goto JbqCL; IiSGP: @close" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule nshell_encoded39a89445_485f_4f92_b2c2_479e5c7a00ce {
   meta:
      description = "php - file nshell-encoded39a89445-485f-4f92-b2c2-479e5c7a00ce.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "a09dcf52da767815f29f66cb7b03f3d8c102da5cf7b69567928961c389eac11f"
   strings:
      $x1 = " goto AQmqN; tSxa6: $LWL4t = @ini_get(\"\\144\\151\\x73\\x61\\x62\\154\\x65\\137\\x66\\x75\\156\\143\\164\\x69\\157\\156\\163\")" ascii
      $s2 = "x75\")) { goto IEXa7; } goto HSchG; yioLg: ob_start(); goto JBq2Q; KROgD: system($xVRuJ); goto ngLG0; iWJ_P: $T_bFi = shell_exec" ascii
      $s3 = "(is_resource($RoC45 = popen($xVRuJ, \"\\x72\"))) { goto VSU5M; } goto XO2OR; ngLG0: $T_bFi = ob_get_contents(); goto BG_PL; W1p8" ascii
      $s4 = "; goto zlSBw; EbF6d: yOsK4: goto OgDes; QQhj6: goto WzhT0; goto L0wPF; oILWD: WzhT0: goto mQI61; YBros: $T_bFi = ob_get_contents" ascii
      $s5 = "    |    GitHub: https://github.com/pk-fr/yakpro-po    |" fullword ascii
      $s6 = "asNg; UE08l: exec($xVRuJ, $T_bFi); goto ZkCQS; ZjC2j: $T_bFi = ''; goto dlfxI; gk2eW: RKDO0: goto W1p8y; VObJI: if (feof($RoC45)" ascii
      $s7 = "TqWd: goto wiKd1; goto tBRS3; mJ6Sd: echo \"\\x75\\163\\x65\\162\\75\" . @get_current_user() . \"\\x20\\165\\151\\144\\75\" . @g" ascii
      $s8 = " && isset($_GET[\"\\x70\\x61\\x73\\163\"])) { goto vXPJ3; } goto GKRHp; MLkKS: $fws1Q = $_SERVER[\"\\104\\x4f\\103\\x55\\x4d\\10" ascii
      $s9 = "3a\\x20{$Ae4rf}\"); goto YtxJl; pZAkH: O20ln($kSYDS); goto YZXTJ; ekB4M: error_reporting(0); goto o2AJ9; gr7AD: echo $h_Sna; got" ascii
      $s10 = "L; } goto xNzOr; VazOf: if (!isset($_GET[\"\\163\\162\\156\\x61\\155\\x65\"])) { goto O3Bt_; } goto tOOkV; hsxuD: $qNA8P = $hBaR" ascii
      $s11 = " KUsBt; IjoY5: dF9er: goto Fs4Y9; dy3uN: $tG1Gs = $_GET[\"\\144\\x65\\154\"]; goto Nc9fP; bebyD: $lhoxm = \"\\x3c\\143\\x65\\x6e" ascii
      $s12 = "x64\\76\\x4f\\x46\\x46\\x3c\\x2f\\x66\\x6f\\x6e\\x74\\x3e\\74\\57\\x62\\x3e\"; goto iTqWd; nHI12: $CVaoI = @zJ9Qd($WL_aq, $_GET[" ascii
      $s13 = "64\\64\\64\\x34\\x34\\x22\\x3e\\xa\\x3c\\x63\\145\\156\\x74\\x65\\x72\\x3e\\12\"; goto whIUs; XUwyw: if (isset($_GET[\"\\163\\16" ascii
      $s14 = "x69\\162\\40\" . $Jd206); } goto DC_rm; gwPfT: @fwrite($ookeh, stripslashes($VOeBC)); goto PByXk; ehh7r: $npdN9 = @$_GET[\"\\141" ascii
      $s15 = "ftKyk; vse2W: $WL_aq = $_GET[\"\\x73\\x72\\156\\141\\x6d\\145\"]; goto kKytA; Gg_CS: if (!($npdN9 == \"\\151\\156\\x66\\x6f\")) " ascii
      $s16 = "156\"; goto dwpGa; iFeV2: $L3Hb5 = $_POST[\"\\163\\x63\\162\\x69\\160\\164\"]; goto Q4kWP; ObnxP: echo \"\\74\\146\\157\\156\\16" ascii
      $s17 = "2\\x3d\\142\\x6c\\x75\\145\\x3e\"; goto e8N14; JXkEU: LuHo2: goto VTM_i; J8GLp: $ykjYY = @ini_get(\"\\x73\\x61\\146\\x65\\137\\1" ascii
      $s18 = "x20\\x67\\x69\\144\\75\" . @getmygid() . \"\\x3c\\57\\x66\\x6f\\156\\164\\x3e\\74\\142\\x72\\76\\x3c\\x62\\76\"; goto ycqNj; EY9" ascii
      $s19 = " goto AQmqN; tSxa6: $LWL4t = @ini_get(\"\\144\\151\\x73\\x61\\x62\\154\\x65\\137\\x66\\x75\\156\\143\\164\\x69\\157\\156\\163\")" ascii
      $s20 = "e($f8CGa, glob(\"\\52\\x2e\\x2a\")); goto VZBDG; ja7Sf: echo $_GET[\"\\x73\\x72\\156\\141\\155\\145\"]; goto VazOf; PSQJ3: echo " ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule PHANTASMA_encoded7ab47c64_3171_4542_b2b4_fcf134afe5fe {
   meta:
      description = "php - file PHANTASMA-encoded7ab47c64-3171-4542-b2b4-fcf134afe5fe.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "9ae8a59f5f48c3ad401057c1f45f28e6d02e4d33f276414c392bcd778c082aea"
   strings:
      $x1 = " goto c8o2O; GiIoI: $CeoAV = fileperms($MkZx7); goto jJETS; HlIUk: if (!(($MkZx7 = readdir($XQ1sR)) !== false)) { goto bxNOw; } " ascii
      $s2 = "$ZWvEG}\\xd\\xa\")) { goto uNURU; } goto q4Swr; WhNPy: $JEFFn = ob_get_contents(); goto w4NMS; g3g_U: uNURU: goto Hiub4; rw0dE: " ascii
      $s3 = " x9844: $l_B4U = gethostbyname($Oyr67); goto eyam1; L7ebI: if (!($RlRgG < $U34T3)) { goto GgdrL; } goto RBXE8; KwlxQ: $lSEBY = @" ascii
      $s4 = "\\x6c\\171\\40\\x43\\x6f\\x70\\x69\\145\\144\\74\\57\\x44\\111\\x56\\x3e\"; goto c0NZE; pQ8Il: $iuzc6 = Getservbyport($V3I1q[$Rl" ascii
      $s5 = "    |    GitHub: https://github.com/pk-fr/yakpro-po    |" fullword ascii
      $s6 = "x6c\\x22\\x3e\"; goto Habd0; EockD: $EvMtF = get_current_user(); goto u73LG; REGuI: nqlJD: goto TQC2b; pB6D_: wxusA: goto pE5TJ;" ascii
      $s7 = "62\\72\\40{$UZyog}\\x20\\74\\x62\\x72\\76\\74\\142\\162\\76\"; goto j7zlu; KO0MX: closelog(); goto EockD; rqGK4: TaTKD: goto INL" ascii
      $s8 = "F; goto wE1OQ; NzuuL: if (!(list($pU3jE, $YpJuN) = each($MgCQn))) { goto k4h01; } goto Z3oFH; VMnLI: $BJqBG = posix_geteuid(); g" ascii
      $s9 = "72\"); goto kfNTz; O_xFH: $EZbe9 = posix_getgid(); goto AoGaj; XKVWp: YwYaF: goto d6QZY; MVlsx: if (!($CBfXg == 1)) { goto ZddwN" ascii
      $s10 = "PFOT; Pk26Y: SjCl9: goto nUZUk; K8poT: Pm51_: goto pYQJH; NeqPj: $aIaHm = getcwd(); goto JV7_s; MuOA2: if (!(@is_writable($MkZx7" ascii
      $s11 = " Y1Sr0; lloWx: if (!(@is_writable($MkZx7) && @is_dir($MkZx7))) { goto XEamH; } goto qVqge; xUuQw: k4h01: goto h0ig7; LGyCf: eval" ascii
      $s12 = "; goto ETcCE; INLyt: if (!(($MkZx7 = readdir($XQ1sR)) !== false)) { goto hBSJt; } goto lloWx; y0hZu: echo str_replace(\"\\76\", " ascii
      $s13 = "pB6D_; E7N4n: if (!(($MkZx7 = readdir($XQ1sR)) !== false)) { goto Pm51_; } goto UFHDR; nFhAO: if (!empty($zZqm1)) { goto nqlJD; " ascii
      $s14 = "pversion(); goto PmpL6; GyFtr: if (!empty($zZqm1)) { goto SjCl9; } goto porcV; jJETS: echo \"\\x3c\\x66\\157\\156\\x74\\40\\x63" ascii
      $s15 = "\\x20\\74\\142\\162\\x3e\\74\\142\\x72\\x3e\"; goto JUtJt; UxVX6: echo \"\\x3c\\57\\124\\101\\x42\\x4c\\x45\\x3e\"; goto CoUao; " ascii
      $s16 = " goto c8o2O; GiIoI: $CeoAV = fileperms($MkZx7); goto jJETS; HlIUk: if (!(($MkZx7 = readdir($XQ1sR)) !== false)) { goto bxNOw; } " ascii
      $s17 = "= fread($lSEBY, 30000); goto elfqH; yRjXA: echo \"\\74\\x62\\76\\74\\x66\\157\\156\\x74\\40\\163\\151\\x7a\\145\\x3d\\x32\\40\\x" ascii
      $s18 = "A: $zZqm1 = fwrite($lSEBY, $cIv7P); goto GyFtr; hJ9Vv: $xFras = @fread($lSEBY, 4096); goto rzGeX; kar1I: ob_start(); goto e_oXK;" ascii
      $s19 = ") && @is_file($MkZx7))) { goto wxusA; } goto QA82H; c19Xo: echo \"\\74\\57\\x44\\111\\x56\\x3e\\74\\57\\124\\104\\x3e\\xa\\40\\4" ascii
      $s20 = "hAO; q6zex: if (!(($MkZx7 = readdir($XQ1sR)) !== false)) { goto o8WIX; } goto MuOA2; yGLGz: echo \"\\x3c\\x46\\x4f\\122\\x4d\\x2" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule MackersPrivatePHPShell_encoded26e554de_bbd6_4b34_a460_6189504a7e51 {
   meta:
      description = "php - file MackersPrivatePHPShell-encoded26e554de-bbd6-4b34-a460-6189504a7e51.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "3da2d3b5bce512c7f10dec30a87e61ba5db0f8ebe7a5d237200090f04e0282cb"
   strings:
      $x1 = " goto FlZgy; mLW5U: sort($kSF3J); goto bdoHL; JLRIn: $NzKTT = array(); goto UBUwn; Y5kGj: echo \"\\x3c\\x62\\162\\x3e\\74\\x62" ascii
      $s2 = ") { goto yLxVr; } goto AMvqh; qnsKA: if (!($O1fi7 > count($AZOge) - 1)) { goto Jwvg_; } goto SSI2P; PQRlP: if (!@is_executable(" ascii
      $s3 = "\\145\\x72\\76\"; goto YEbX_; w_Jgv: if (!(count($AZOge) - 1 > $CLO2d)) { goto EQW4w; } goto bZqen; stcmd: if ($F10uG[1][0] == " ascii
      $s4 = "ZZn2; YNGnl: $rfAzR = $qLz8K * $CLO2d; goto jEusv; DGbM1: if (!(ini_get(\"\\162\\145\\x67\\151\\163\\x74\\x65\\x72\\137\\x67\\x6" ascii
      $s5 = "if (!($Z597Z = readdir($d_9ju))) { goto EaBOu; } goto S6QjD; ktLQP: error_reporting(0); goto z4QFu; juoJS: echo $O1hlO; goto iu5" ascii
      $s6 = "\\x72\\x3e\"; goto UdgJA; xgy17: hqbbr: goto FRZ5b; dm0IR: goto ZDvp5; goto Tj_mv; yevEV: $QxuGs = exec(\"\\x70\\167\\144\"); go" ascii
      $s7 = "    |    GitHub: https://github.com/pk-fr/yakpro-po    |" fullword ascii
      $s8 = "ogE; vEMC2: $gvOsj = ''; goto MRQzY; pvi8r: goto BW35m; goto BURvW; k5aZW: $O1fi7 = count($AZOge) - 1; goto XpT2j; SwcWI: if (!(" ascii
      $s9 = "x74\\x72\\76\\74\\x2f\\x63\\x65\\156\\164\\x65\\162\\x3e\"; goto Jeu9O; WPlWc: if (!(($JPwSq + 1) * $CLO2d + $CLO2d / 2 < count(" ascii
      $s10 = " cGC4z; vmaCi: $O1fi7 = ($JPwSq + 1) * $CLO2d - 1; goto XI4r2; Hjx4r: $kSF3J = array(); goto q0V1W; jEusv: $O1fi7 = ($qLz8K + 1)" ascii
      $s11 = " ($KR2g8 != false) { goto YriiH; } goto E5jLX; SSI2P: $O1fi7 = count($AZOge) - 1; goto x4lmc; HBoAJ: echo \"\\x3c\\151\\x6e\\160" ascii
      $s12 = "$_POST); goto zxxL7; j25pG: if (!@is_readable(\"{$c2MxH}\\x2f{$x6VBn}\")) { goto CKHsd; } goto zlGpZ; SwJUY: echo gC3QB(wlEbP(2)" ascii
      $s13 = " * $CLO2d - 1; goto S42CB; dLI8l: echo \"\\x3c\\x66\\157\\162\\155\\40\\x61\\x63\\164\\x69\\x6f\\x6e\\x3d\\42{$Nuw2T}\\x3f{$cO_7" ascii
      $s14 = "0\\73\\46\\156\\142\\163\\160\\x3b\"; goto lG6hA; PjE1F: $QlpwV = 1; goto H73r2; RR7n1: G2YgL: goto WW8d0; nOx5g: if (!@is_execu" ascii
      $s15 = "SAw: if (!@is_executable(\"{$c2MxH}\\x2f{$x6VBn}\")) { goto cmpyV; } goto AoYe0; sZwcq: U6um2: goto Tt22r; F237E: b4aCt: goto Ra" ascii
      $s16 = "165\\x74\\141\\142\\154\\145\\56\\x3c\\57\\x74\\144\\x3e\\74\\x2f\\x74\\x72\\x3e\\xa\"; goto rUYPP; cY8Gu: if (count($AZOge) - 1" ascii
      $s17 = "KT; wPq5P: goto BW35m; goto B8sRN; lAglW: alvfE: goto yevEV; S42CB: if (!($O1fi7 - count($AZOge) - 1 + $CLO2d / 2 > 0)) { goto s" ascii
      $s18 = "o Lf6Sz; a0Thc: $O1fi7 = count($AZOge) - 1; goto Fex6U; aOIIP: goto Tt332; goto Qu2_I; uppla: $A4MW8 = substr($AIAj_, $IRbQh + 1" ascii
      $s19 = "_: $PE3hj = tempnam(\"\\x2f\\x74\\x6d\\160\", \"\\x70\\x68\\x70\\x73\\x68\\x65\\x6c\\x6c\"); goto iWfko; JWziQ: iE54m: goto lzG0" ascii
      $s20 = "sTaag); goto NjVlI; BZIbe: @closedir($vztOp); goto MgPCJ; dJYQD: if (!($k9HMi = readdir($vztOp))) { goto MfuGJ; } goto acZbI; C9" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule NCC_Shell_encodeda8b8ca34_3cac_4c13_a828_6e8ce80fb433 {
   meta:
      description = "php - file NCC-Shell-encodeda8b8ca34-3cac-4c13-a828-6e8ce80fb433.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "401388d8b97649672d101bf55694dd175375214386253d0b4b8d8d801a89549c"
   strings:
      $s1 = "    |    GitHub: https://github.com/pk-fr/yakpro-po    |" fullword ascii
      $s2 = "6\\x3c\\x2f\\x62\\76\"; goto l8gey; aPGV7: d7KFf: goto fVub0; Y_ckZ: @phpinfo(); goto K03cW; ZxkK8: if (!(@$_GET[\"\\160\"] == " ascii
      $s3 = "8qPO: if (ini_get(\"\\163\\141\\146\\145\\x5f\\155\\157\\144\\x65\")) { goto d7KFf; } goto ORF03; c6t1X: echo \"\\x3c\\x62\\76" ascii
      $s4 = " goto KJmuk; gd2Zt: echo \"\\74\\142\\x3e\\74\\146\\157\\x6e\\x74\\x20\\143\\x6f\\x6c\\157\\x72\\75\\x72\\145\\144\\76\\x53\\x61" ascii
      $s5 = "9\\x70\\114\\x6f\\147\\147\\145\\x72\\74\\x2f\\x68\\62\\x3e\\12\"; goto ddfyn; laCx0: eval(base64_decode($Yx6RF)); goto gd2Zt; q" ascii
      $s6 = "5\"; goto laCx0; d_aIp: move_uploaded_file($_FILES[\"\\x70\\x72\\x6f\\x62\\x65\"][\"\\x74\\x6d\\160\\137\\x6e\\141\\x6d\\145\"]," ascii
      $s7 = "\\146\\157\")) { goto I0pUW; } goto Y_ckZ; ORF03: print \"\\74\\x66\\x6f\\156\\x74\\x20\\x63\\157\\154\\157\\x72\\x3d\\43\\60\\x" ascii
      $s8 = "\\x64\\145\\x20\\x4f\\116\\x3c\\57\\142\\76\\74\\x2f\\146\\x6f\\156\\x74\\x3e\"; goto IXy_D; pIoPn: printf(\"\\104\\x69\\145\\40" ascii
      $s9 = "157\\74\\x2f\\141\\76\"; goto ZxkK8; fRinS: echo \"\\76\\x3c\\x68\\162\\x3e\\x3c\\160\\x72\\x65\\x3e\\74\\77\\151\\x66\\x28\\x24" ascii
      $s10 = "x3a\\40\\74\\57\\146\\157\\x6e\\164\\76\\x3c\\57\\142\\x3e\"; goto e9FLn; Mk7Oq: echo $_SERVER[\"\\122\\x45\\x4d\\117\\x54\\105" ascii
      $s11 = "fVub0: print \"\\74\\x66\\157\\156\\164\\40\\x63\\x6f\\154\\157\\x72\\x3d\\x23\\106\\x46\\60\\60\\60\\x30\\x3e\\74\\x62\\x3e\\12" ascii
      $s12 = "4\\145\\x6e\\56\\x3c\\142\\162\\x20\\x2f\\76\\xa\", $_FILES[\"\\160\\x72\\157\\x62\\145\"][\"\\x6e\\141\\155\\145\"]); goto CbDP" ascii
      $s13 = "oto U9KBQ; e9FLn: echo $_SERVER[de17A]; goto sSHcY; QlD95: $Yx6RF = \"\\x4a\\x48\\132\\x70\\143\\x32\\154\\x30\\x59\\171\\x41\\7" ascii
      $s14 = "set($_FILES[\"\\160\\x72\\x6f\\142\\x65\"]) and !$_FILES[\"\\160\\162\\x6f\\142\\x65\"][\"\\145\\x72\\x72\\x6f\\x72\"])) { goto " ascii
      $s15 = "\"]; goto kWwSy; l8gey: echo $_SERVER[\"\\x48\\x54\\124\\120\\137\\x55\\x53\\105\\x52\\x5f\\x41\\x47\\x45\\116\\x54\"]; goto R0g" ascii
      $s16 = "oto Mk7Oq; ddfyn: echo \"\\x3c\\x62\\x3e\\74\\x66\\157\\156\\164\\x20\\x63\\157\\x6c\\157\\x72\\75\\162\\145\\x64\\x3e\\x3c\\142" ascii
      $s17 = "]; goto j71i6; YxwTK: echo \"\\74\\x61\\x20\\150\\x72\\145\\146\\75\\x27{$JDp4H}\\77\\x70\\75\\151\\156\\146\\157\\47\\x3e\\120" ascii
      $s18 = "2f\\x44\\x61\\x74\\x65\\x69\\74\\57\\164\\151\\164\\x6c\\x65\\x3e\\xa\\74\\x66\\157\\x72\\155\\12\\x20\\x61\\x63\\x74\\151\\157" ascii
      $s19 = "04\\122\"]; goto c6t1X; kWwSy: echo \"\\42\\xa\\40\\155\\x65\\164\\150\\157\\144\\x3d\\42\\x70\\x6f\\x73\\164\\x22\\xa\\40\\x65" ascii
      $s20 = " goto KJmuk; gd2Zt: echo \"\\74\\142\\x3e\\74\\146\\157\\x6e\\x74\\x20\\143\\x6f\\x6c\\157\\x72\\75\\x72\\145\\144\\76\\x53\\x61" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 30KB and
      8 of them
}

rule upload2f4bfd20_754d_42bc_97cf_fdd79e558de7 {
   meta:
      description = "php - file upload2f4bfd20-754d-42bc-97cf-fdd79e558de7.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "30ead04581322268b77fee51c43123621c74271b42da505a39c14d2e54860d4e"
   strings:
      $s1 = "<center><form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">" fullword ascii
      $s2 = "<?php if( $_POST['_upl'] == \"Upload\" ) { if(@copy($_FILES['file']['tmp_name'], $_FILES['file']['name'])) { echo 'Done !!'; } e" ascii
      $s3 = "<?php if( $_POST['_upl'] == \"Upload\" ) { if(@copy($_FILES['file']['tmp_name'], $_FILES['file']['name'])) { echo 'Done !!'; } e" ascii
      $s4 = "echo \"<center><p><br><b>\".getcwd().\"</b><br></p></center>\";" fullword ascii
      $s5 = "e { echo 'Failed :('; }} " fullword ascii
      $s6 = "<center><input type=\"file\" name=\"file\" size=\"50\"><input name=\"_upl\" type=\"submit\" id=\"_upl\" value=\"Upload\"></form>" ascii
      $s7 = "echo \"<center><br><b>\".php_uname().\"</b><br></center>\";" fullword ascii
   condition:
      uint16(0) == 0x633c and filesize < 1KB and
      all of them
}

rule Safe0verShell_SafeModBypassByEvilc0der_encodedcf5d0c6d_51f2_4c65_b986_4e93ef384f95 {
   meta:
      description = "php - file Safe0verShell-SafeModBypassByEvilc0der-encodedcf5d0c6d-51f2-4c65-b986-4e93ef384f95.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "ecb59f89a7f9762e72233b16b43d76ff0a32af1977b5acefcdf2c3e15f2172b9"
   strings:
      $x1 = " goto VwTjl; S058f: echo \"\\x3c\\146\\157\\x72\\x6d\\40\\x61\\x63\\x74\\151\\157\\156\\75\\x22{$bo42n}\\77{$uv4Dy}\\42\\40\\155" ascii
      $s2 = "    |     Safe Over Shell - leetc0des.blogspot.com     |" fullword ascii
      $s3 = "(!($QXgqw > count($I60Mv) - 1)) { goto JIVy3; } goto k5_Wq; gRwSE: if (!isset($_POST)) { goto r1LxE; } goto s_UdN; JamRW: exit; " ascii
      $s4 = "* $viuj3 + $viuj3 / 2 < count($I60Mv) - 1)) { goto aMc_i; } goto m7Cel; zq8F9: yGAeS: goto UM1Oh; PX4rP: if (!file_exists(\"{$sB" ascii
      $s5 = "\\12\"; goto VzjzO; yaUTY: $CG1PB = \"\\74\\55\\x2d\\40\\40\\x20\\x2e\\56\\x2e\" . substr($CG1PB, $Bvobn); goto ueJPe; A3iIL: if" ascii
      $s6 = "to MnZGR; ijmD_: $V0ekj = \"\\146\\151\\x6c\\x65\"; goto CvSU8; Q2LDB: if (!@is_executable(\"{$jpGRP}\\57{$XL52U}\")) { goto dN0" ascii
      $s7 = "goto oGR8z; uUhmY: echo $NiZQ4; goto Xh2h3; ZaOsY: if (!($QXgqw - count($I60Mv) - 1 + $viuj3 / 2 > 0)) { goto YvDCR; } goto iLVB" ascii
      $s8 = "_dir(\"{$jpGRP}\\x2f{$wvW1x}\")) { goto k4W5W; } goto zQf0r; k5_Wq: $QXgqw = count($I60Mv) - 1; goto eV8uG; TQ1Jf: echo \"{$V0ek" ascii
      $s9 = "_exists($wVPvw)) { goto ouIT3; } goto bFQmp; rVnkN: if (!(count($I60Mv) - 1 > $viuj3)) { goto QE2so; } goto Mang3; hZNKP: rbTxA:" ascii
      $s10 = "jSFv: if (!@is_executable(\"{$jpGRP}\\57{$XL52U}\")) { goto Djb4D; } goto HQIZA; JNAWU: echo \"\\40\\x20\\x20\\x20\\x3c\\x74\\x6" ascii
      $s11 = "qw = ($ueV8r + 1) * $viuj3 - 1; goto JFpON; fw4kn: IKpU1: goto jVD2c; WxGGG: $AXhIv = \"\\x69\\155\\x67\"; goto cp25B; vbH0i: $S" ascii
      $s12 = "$I60Mv) - 1; goto t_oaV; yOxNa: Tj3EE: goto GSpRW; aTnMV: xtg1u: goto bo65w; ovUPb: goto Z8Umk; goto qibFN; lUEQe: echo \"\\74" ascii
      $s13 = "20\\x76\\141\\x6c\\165\\x65\\75\\42\"; goto Je_JU; g4NRx: if (count($I60Mv) - 1 > $viuj3) { goto PEnYK; } goto IQpCP; BcWTP: $at" ascii
      $s14 = "7\\164\\144\\76\\x3c\\x2f\\164\\162\\x3e\\12\"; goto uhixi; iLVBy: $QXgqw = count($I60Mv) - 1; goto eK49m; IQpCP: $OJIu7 = $I60M" ascii
      $s15 = "I: $QXgqw = ($kTHhB + 1) * $viuj3 - 1; goto ZaOsY; HlaIy: $CG1PB = substr($CG1PB, -100); goto JgaEu; M5swl: echo \"\\74\\151\\15" ascii
      $s16 = ": SbRld: goto OfAZx; XVxIJ: $VDS90 = substr($OnQbx, $C6iSh + 1); goto m2eId; BV7De: if (!(isset($suzHV) && isset($fFq7_) && (!is" ascii
      $s17 = "jpGRP); goto YINW9; kDNGl: if (!(@is_writeable(\"{$jpGRP}\\x2f{$XL52U}\") && @is_readable(\"{$jpGRP}\\57{$XL52U}\"))) { goto WIq" ascii
      $s18 = " (!(@is_writeable(\"{$jpGRP}\\57{$XL52U}\") && @is_readable(\"{$jpGRP}\\57{$XL52U}\"))) { goto qcXTZ; } goto Lj7_3; NhRPs: goto " ascii
      $s19 = "\\x26\\144\\x69\\162\\x3d{$jpGRP}\\x26\\x50\\151\\x64\\170\\75{$ueV8r}\"; goto x6GPp; s_UdN: XiXAF($_POST); goto xqhsF; SDkD8: e" ascii
      $s20 = "\\12\"; goto DTarT; YX76t: if (!isset($_GET)) { goto notNc; } goto xuuty; VdOVe: usort($SyA8M, \"\\x6d\\171\\143\\x6d\\x70\"); g" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule PHVayv_encoded637fa391_c908_49e4_aed4_2b92de774fbd {
   meta:
      description = "php - file PHVayv-encoded637fa391-c908-49e4-aed4-2b92de774fbd.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "baa6ea891c3696a6cd1e1a5c435894bdb53ab4869c7f52b84494c27dd5d54103"
   strings:
      $s1 = "    |          PHVayv - leetc0des.blogspot.com         |" fullword ascii
      $s2 = " echo \"\\x3c\\77\\x20\\x69\\146\\50\\44\\x73\\x69\\x73\\x74\\x65\\x6d\\x62\\x69\\x6c\\147\\151\\x73\\x69\\x20\\x3e\\x20\\42\\x2" ascii
      $s3 = " echo \"\\x3c\\77\\x20\\x69\\146\\50\\44\\x73\\x69\\x73\\x74\\x65\\x6d\\x62\\x69\\x6c\\147\\151\\x73\\x69\\x20\\x3e\\x20\\42\\x2" ascii
      $s4 = "\\x6e\\x74\\147\\162\\x75\\160\\x2e\\x6e\\x65\\164\\x22\\x20\\163\\164\\171\\x6c\\145\\x3d\\x22\\x74\\x65\\170\\x74\\55\\144\\14" ascii
      $s5 = "\\145\\162\\144\\x61\\x6e\\141\\x22\\40\\x73\\164\\171\\x6c\\x65\\x3d\\42\\x66\\x6f\\156\\164\\55\\163\\151\\x7a\\145\\x3a\\40" ascii
      $s6 = "\\55\\x64\\145\\x63\\157\\x72\\x61\\164\\151\\157\\x6e\\72\\40\\156\\157\\156\\145\\42\\x3e\\15\\xa\\x20\\40\\x20\\40\\x20\\40" ascii
      $s7 = "\\117\\125\\x4e\\x44\\55\\x43\\117\\x4c\\117\\122\\x3a\\x20\\43\\145\\x61\\145\\x39\\145\\x39\\73\\x20\\102\\x4f\\x52\\104\\x45" ascii
      $s8 = "\\xa\\x20\\40\\40\\x20\\x3c\\x69\\155\\x67\\x20\\142\\157\\x72\\x64\\x65\\x72\\x3d\\x22\\60\\x22\\x20\\163\\x72\\143\\x3d\\x22" ascii
      $s9 = "\\156\\x3d\\x22\\x30\\42\\x3e\\xd\\xa\\74\\164\\x61\\142\\x6c\\x65\\x20\\142\\157\\162\\x64\\x65\\162\\75\\x22\\61\\42\\x20\\x63" ascii
      $s10 = "\\x79\\145\\156\\144\\x6f\\x73\\75\\61\\x26\\x64\\x69\\172\\x69\\156\\75\\x24\\x64\\x69\\172\\x69\\x6e\\42\\73\\x3f\\x3e\\x22\\4" ascii
      $s11 = "\\x22\\x3b\\77\\76\\x22\\x20\\163\\x74\\x79\\154\\145\\75\\x22\\164\\145\\170\\x74\\x2d\\x64\\x65\\x63\\157\\x72\\141\\x74\\x69" ascii
      $s12 = "\\x29\\x3b\\175\\x7b\\44\\144\\151\\172\\151\\x6e\\75\\162\\145\\x61\\154\\x70\\141\\x74\\150\\50\\44\\x64\\151\\172\\151\\156" ascii
      $s13 = "\\x20\\40\\40\\x20\\x20\\x20\\40\\x20\\x20\\40\\40\\74\\x74\\144\\x3e\\74\\146\\157\\x6e\\164\\x20\\x66\\141\\143\\x65\\75\\42" ascii
      $s14 = "\\x6c\\x6c\\141\\x70\\x73\\145\\x22\\40\\x62\\x6f\\162\\x64\\x65\\162\\x63\\x6f\\x6c\\157\\162\\x3d\\x22\\x23\\x31\\61\\61\\61" ascii
      $s15 = "\\61\\x52\\x66\\126\\x56\\x4a\\x4a\\x49\\x6c\\60\\67\\x44\\121\\x6f\\147\\111\\x43\\122\\60\\x59\\x58\\x4a\\x6e\\132\\x58\\121" ascii
      $s16 = "\\x70\\73\\x3c\\142\\x72\\76\\15\\xa\\x20\\x20\\40\\x20\\x3c\\x2f\\x66\\x6f\\x6e\\164\\76\\74\\57\\163\\160\\x61\\156\\x3e\\74" ascii
      $s17 = "\\x20\\x73\\x74\\171\\x6c\\x65\\75\\x22\\x62\\x6f\\162\\x64\\145\\162\\x2d\\x63\\x6f\\x6c\\x6c\\x61\\x70\\163\\x65\\72\\x20\\x63" ascii
      $s18 = "\\x20\\x20\\x3c\\160\\40\\x61\\x6c\\x69\\x67\\x6e\\75\\x22\\x72\\x69\\x67\\150\\x74\\42\\76\\x3c\\x73\\160\\x61\\x6e\\x20\\x73" ascii
      $s19 = "\\xd\\xa\\40\\40\\x20\\40\\x20\\x20\\x20\\x20\\x20\\x20\\x20\\40\\x20\\40\\40\\x20\\163\\164\\171\\x6c\\x65\\75\\42\\x43\\125\\1" ascii
      $s20 = "\\156\\57\\x24\\144\\165\\172\\x65\\x6e\\x6c\\x65\\x22\\77\\76\\74\\57\\x66\\x6f\\156\\x74\\76\\74\\57\\x74\\x64\\x3e\\15\\xa\\4" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 300KB and
      8 of them
}

rule securityghost_priv_Zero5eca1494b_2c16_412d_961c_a19841df04a5 {
   meta:
      description = "php - file securityghost-priv-Zero5eca1494b-2c16-412d-961c-a19841df04a5.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "6cd9596d60669360cec589f005134372e85a7673917644e1d8b3a24554362da7"
   strings:
      $x1 = "XFAoQegwrL3wrL3wrLUvsIQjSP7BX8/NHVC0oUg8V2A/oUO0ZmW0WMGKpDgwreOBpvaBZMW0WMBKpDgwrLaBreOB4mcwpDOBrLaBreOxQeOBpvaBpDOBrmCKpvaBreOB" ascii
      $s2 = "c191cGxvYWRlZF9maWxlJzskSUlJSUlJbElJSUlsPSdmbHVzaCc7JElJSUlJSWxJSUlJST0nb2JfZmx1c2gnOyRJSUlJSUlJMTExMTE9J3ByZWdfbWF0Y2gnOyRJSUlJ" ascii /* base64 encoded string 's_uploaded_file';$IIIIIIlIIIIl='flush';$IIIIIIlIIIII='ob_flush';$IIIIIII11111='preg_match';$IIII' */
      $s3 = "PSdpc19maWxlJzskSUlJSUlJSWxsbGxJPSdyZWFkZGlyJzskSUlJSUlJSWxsbEkxPSdvcGVuZGlyJzskSUlJSUlJSWxsSWxsPSd0cmltJzskSUlJSUlJSWxJbGwxPSdw" ascii /* base64 encoded string '='is_file';$IIIIIIIllllI='readdir';$IIIIIIIlllI1='opendir';$IIIIIIIllIll='trim';$IIIIIIIlIll1='p' */
      $s4 = "SUlsSUkxST0nc3lzdGVtJzskSUlJSUlJSWxJSWwxPSdvYl9zdGFydCc7JElJSUlJSUlsSUlsbD0nc2hlbGxfZXhlYyc7JElJSUlJSUlsSUlsST0nam9pbic7JElJSUlJ" ascii /* base64 encoded string 'IIlII1I='system';$IIIIIIIlIIl1='ob_start';$IIIIIIIlIIll='shell_exec';$IIIIIIIlIIlI='join';$IIIII' */
      $s5 = "aXBzbGFzaGVzJzskSUlJSUlJSTExbElJPSdzZXRfdGltZV9saW1pdCc7JElJSUlJSWxJMUlsST0naW5pX3NldCc7JElJSUlJSUlJSWxJbD0naGVhZGVyJzskSUlJSUlJ" ascii /* base64 encoded string 'ipslashes';$IIIIIII11lII='set_time_limit';$IIIIIIlI1IlI='ini_set';$IIIIIIIIIlIl='header';$IIIIII' */
      $s6 = "SUlJbElsSUkxPSdoZXhkZWMnOyRJSUlJSUlsSWxJSWw9J3NoYTEnOyRJSUlJSUlsSUkxMWw9J29yZCc7JElJSUlJSWxJSTExST0nY2hyJzskSUlJSUlJbElJSUkxPSdp" ascii /* base64 encoded string 'IIIlIlII1='hexdec';$IIIIIIlIlIIl='sha1';$IIIIIIlII11l='ord';$IIIIIIlII11I='chr';$IIIIIIlIIII1='i' */
      $s7 = "cmUnOyRJSUlJSUlsbGwxSWw9J2Jhc2U2NF9lbmNvZGUnOyRJSUlJSUlsbGxsMUk9J2h0bWxlbnRpdGllcyc7JElJSUlJSWxsSTFsMT0nY3J5cHQnOyRJSUlJSUlsbEkx" ascii /* base64 encoded string 're';$IIIIIIlll1Il='base64_encode';$IIIIIIllll1I='htmlentities';$IIIIIIllI1l1='crypt';$IIIIIIllI1' */
      $s8 = "X3B1c2gnOyRJSUlJSUlJMUkxMUk9J215c3FsX2ZldGNoX3Jvdyc7JElJSUlJSUkxSTFsbD0nbXlzcWxfbGlzdF90YWJsZXMnOyRJSUlJSUlJMUlsMTE9J215c3FsX2dl" ascii /* base64 encoded string '_push';$IIIIIII1I11I='mysql_fetch_row';$IIIIIII1I1ll='mysql_list_tables';$IIIIIII1Il11='mysql_ge' */
      $s9 = "bGw9J215c3FsX2Nvbm5lY3QnOyRJSUlJSUlJMUlJSWw9J2ZpbGVwZXJtcyc7JElJSUlJSUlsMTFJbD0nZndyaXRlJzskSUlJSUlJSWwxbGxsPSdmY2xvc2UnOyRJSUlJ" ascii /* base64 encoded string 'll='mysql_connect';$IIIIIII1IIIl='fileperms';$IIIIIIIl11Il='fwrite';$IIIIIIIl1lll='fclose';$IIII' */
      $s10 = "ZSc7JElJSUlJSUlJSWxsbD0nb2JfY2xlYW4nOyRJSUlJSUlJSUlsbEk9J2d6ZW5jb2RlJzskSUlJSUlJSUlJbEkxPSdiYXNlbmFtZSc7JElJSUlJSUlsbEkxST0nc3Ry" ascii /* base64 encoded string 'e';$IIIIIIIIIlll='ob_clean';$IIIIIIIIIllI='gzencode';$IIIIIIIIIlI1='basename';$IIIIIIIllI1I='str' */
      $s11 = "bGw9J3JtZGlyJzskSUlJSUlJbDFJMTExPSdubDJicic7JElJSUlJSWwxSTExbD0naGlnaGxpZ2h0X3N0cmluZyc7JElJSUlJSWwxSTExST0nd29yZHdyYXAnOyRJSUlJ" ascii /* base64 encoded string 'll='rmdir';$IIIIIIl1I111='nl2br';$IIIIIIl1I11l='highlight_string';$IIIIIIl1I11I='wordwrap';$IIII' */
      $s12 = "aGRpcic7JElJSUlJSUlJbElJMT0naXNfZGlyJzskSUlJSUlJSUlsSUlJPSdzdWJzdHInOyRJSUlJSUlJSUkxMWw9J3N0cnRvbG93ZXInOyRJSUlJSUlJSUkxMUk9J2lu" ascii /* base64 encoded string 'hdir';$IIIIIIIIlII1='is_dir';$IIIIIIIIlIII='substr';$IIIIIIIII11l='strtolower';$IIIIIIIII11I='in' */
      $s13 = "aSc7JElJSUlJSWxJMWxsST0nZmlsZSc7JElJSUlJSWxJMWxJST0nc3ltbGluayc7JElJSUlJSWxJMUlJST0ndW5saW5rJzskSUlJSUlJbElsMWxsPSd0aW1lJzskSUlJ" ascii /* base64 encoded string 'i';$IIIIIIlI1llI='file';$IIIIIIlI1lII='symlink';$IIIIIIlI1III='unlink';$IIIIIIlIl1ll='time';$III' */
      $s14 = "SUlJbDFsbEk9J2ZwdXRzJzskSUlJSUlJSWwxbEkxPSdmb3Blbic7JElJSUlJSUlsMWxJbD0nYmFzZTY0X2RlY29kZSc7JElJSUlJSUlsMWxJST0nZ3ppbmZsYXRlJzsk" ascii /* base64 encoded string 'IIIl1llI='fputs';$IIIIIIIl1lI1='fopen';$IIIIIIIl1lIl='base64_decode';$IIIIIIIl1lII='gzinflate';$' */
      $s15 = "bGw9J215c3FsX2Vycm9yJzskSUlJSUlJbGxJbDFsPSdmc29ja29wZW4nOyRJSUlJSUlsbElsMUk9J2lzX251bWVyaWMnOyRJSUlJSUlsbElsSWw9J2FycmF5X3VuaXF1" ascii /* base64 encoded string 'll='mysql_error';$IIIIIIllIl1l='fsockopen';$IIIIIIllIl1I='is_numeric';$IIIIIIllIlIl='array_uniqu' */
      $s16 = "dF9wcm90b19pbmZvJzskSUlJSUlJSTFJbDFsPSdteXNxbF9nZXRfc2VydmVyX2luZm8nOyRJSUlJSUlJMUlsMUk9J2h0bWxzcGVjaWFsY2hhcnMnOyRJSUlJSUlJMUls" ascii /* base64 encoded string 't_proto_info';$IIIIIII1Il1l='mysql_get_server_info';$IIIIIII1Il1I='htmlspecialchars';$IIIIIII1Il' */
      $s17 = "STFsbElJPSdteXNxbF9mZXRjaF9hc3NvYyc7JElJSUlJSUkxbEkxST0nY2VpbCc7JElJSUlJSUkxbElJbD0nbXlzcWxfcXVlcnknOyRJSUlJSUlJMUkxMWw9J2FycmF5" ascii /* base64 encoded string 'I1llII='mysql_fetch_assoc';$IIIIIII1lI1I='ceil';$IIIIIII1lIIl='mysql_query';$IIIIIII1I11l='array' */
      $s18 = "Y2xvc2UnOyRJSUlJSUlJbElsbGw9J2ZyZWFkJzskSUlJSUlJSWxJbGxJPSdmZW9mJzskSUlJSUlJSWxJbEkxPSdwb3Blbic7JElJSUlJSUlsSWxJbD0naXNfcmVzb3Vy" ascii /* base64 encoded string 'close';$IIIIIIIlIlll='fread';$IIIIIIIlIllI='feof';$IIIIIIIlIlI1='popen';$IIIIIIIlIlIl='is_resour' */
      $s19 = "J2N1cmxfZXhlYyc7JElJSUlJSUkxMTFJST0nY3VybF9zZXRvcHQnOyRJSUlJSUlJMTFsMTE9J2N1cmxfaW5pdCc7JElJSUlJSUkxMWwxST0ndXJsZW5jb2RlJzskSUlJ" ascii /* base64 encoded string ''curl_exec';$IIIIIII111II='curl_setopt';$IIIIIII11l11='curl_init';$IIIIIII11l1I='urlencode';$III' */
      $s20 = "SUlJMTExMUk9J3ByZWdfcmVwbGFjZSc7JElJSUlJSUkxMTFsST0ncHJlZ19tYXRjaF9hbGwnOyRJSUlJSUlJMTExSTE9J2N1cmxfY2xvc2UnOyRJSUlJSUlJMTExSWw9" ascii /* base64 encoded string 'III1111I='preg_replace';$IIIIIII111lI='preg_match_all';$IIIIIII111I1='curl_close';$IIIIIII111Il=' */
   condition:
      uint16(0) == 0x3f3c and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule IndoXploit80d892b3_9224_4cc5_a04c_a301b133cf4e {
   meta:
      description = "php - file IndoXploit80d892b3-9224-4cc5-a04c-a301b133cf4e.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "12a41c33e03d83509d43b1917c7ba70d71f4673014fadaa39505a23ec8916916"
   strings:
      $s1 = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
      $s2 = "MTE9J2ZpbGVncm91cCc7JElJSUlJSWxJMTFsMT0nZmlsZW10aW1lJzskSUlJSUlJbEkxMWxJPSdmaWxldHlwZSc7JElJSUlJSWxJMWxsMT0ncm1kaXInOyRJSUlJSUls" ascii /* base64 encoded string '11='filegroup';$IIIIIIlI11l1='filemtime';$IIIIIIlI11lI='filetype';$IIIIIIlI1ll1='rmdir';$IIIIIIl' */
      $s3 = "X21hdGNoX2FsbCc7JElJSUlJSUlJMWxJST0nY3VybF9jbG9zZSc7JElJSUlJSUlJMUkxMT0nY3VybF9leGVjJzskSUlJSUlJSUkxSTFJPSdjdXJsX3NldG9wdCc7JElJ" ascii /* base64 encoded string '_match_all';$IIIIIIII1lII='curl_close';$IIIIIIII1I11='curl_exec';$IIIIIIII1I1I='curl_setopt';$II' */
      $s4 = "SUlJSUlJSWwxSTFJPSdmb3Blbic7JElJSUlJSUlsMUlsST0nZGlybmFtZSc7JElJSUlJSUlsMUlJMT0ndW5saW5rJzskSUlJSUlJSWxsMTFsPSdpc19kaXInOyRJSUlJ" ascii /* base64 encoded string 'IIIIIIIl1I1I='fopen';$IIIIIIIl1IlI='dirname';$IIIIIIIl1II1='unlink';$IIIIIIIll11l='is_dir';$IIII' */
      $s5 = "SUlJSUlJMUlsMT0nY3VybF9pbml0JzskSUlJSUlJSUkxSUlsPSdzdWJzdHInOyRJSUlJSUlJSWwxMUk9J3N0cnBvcyc7JElJSUlJSUlJbDFJbD0nc3ByaW50Zic7JElJ" ascii /* base64 encoded string 'IIIIII1Il1='curl_init';$IIIIIIII1IIl='substr';$IIIIIIIIl11I='strpos';$IIIIIIIIl1Il='sprintf';$II' */
      $s6 = "ST0nb2Jfc3RhcnQnOyRJSUlJSUlJSWxJSUk9J2lzX3JlYWRhYmxlJzskSUlJSUlJSUlJMTFsPSdpc193cml0YWJsZSc7JElJSUlJSUlJSTFsST0nYmFzZTY0X2RlY29k" ascii /* base64 encoded string 'I='ob_start';$IIIIIIIIlIII='is_readable';$IIIIIIIII11l='is_writable';$IIIIIIIII1lI='base64_decod' */
      $s7 = "bDE9J2NoZGlyJzskSUlJSUlJSWxJbGxsPSdzdHJpcHNsYXNoZXMnOyRJSUlJSUlJbElsbEk9J2FycmF5X21hcCc7JElJSUlJSUlsSWxJMT0naXNfYXJyYXknOyRJSUlJ" ascii /* base64 encoded string 'l1='chdir';$IIIIIIIlIlll='stripslashes';$IIIIIIIlIllI='array_map';$IIIIIIIlIlI1='is_array';$IIII' */
      $s8 = "SUlJbGxsbDE9J2NvcHknOyRJSUlJSUlJbGxsSWw9J3Bvc2l4X2dldHB3dWlkJzskSUlJSUlJSWxsSTExPSdnZXRteWdpZCc7JElJSUlJSUlsbEkxST0nZ2V0bXl1aWQn" ascii /* base64 encoded string 'IIIllll1='copy';$IIIIIIIlllIl='posix_getpwuid';$IIIIIIIllI11='getmygid';$IIIIIIIllI1I='getmyuid'' */
      $s9 = "SUlJSUlJbGwxST0nZmlsZXBlcm1zJzskSUlJSUlJSUlsbGxJPSdzaGVsbF9leGVjJzskSUlJSUlJSUlsbEkxPSdwYXNzdGhydSc7JElJSUlJSUlJbEkxMT0nZXhlYyc7" ascii /* base64 encoded string 'IIIIIIll1I='fileperms';$IIIIIIIIlllI='shell_exec';$IIIIIIIIllI1='passthru';$IIIIIIIIlI11='exec';' */
      $s10 = "b3NlJzskSUlJSUlJSTFsbEkxPSdteXNxbF9lcnJvcic7JElJSUlJSUkxbEkxbD0nbXlzcWxfZmV0Y2hfYXJyYXknOyRJSUlJSUlJMWxJMUk9J215c3FsX3F1ZXJ5Jzsk" ascii /* base64 encoded string 'ose';$IIIIIII1llI1='mysql_error';$IIIIIII1lI1l='mysql_fetch_array';$IIIIIII1lI1I='mysql_query';$' */
      $s11 = "Sq3JXNi9bNxC78g5XIrCYEiTWIs5SPyCYPk16V3KYETJX8/hY+/hW8cTW8cJX8/dW8H5X8ckSMaOspiNX+iPYESOZq2tWmCCHoCFWmgxX+UkZq7vHoW5SI7MX8kNo+JD" ascii
      $s12 = "aW5pX3NldCc7JElJSUlJSUlJSUlJMT0nY2xlYXJzdGF0Y2FjaGUnOyRJSUlJSUlJSUlJSWw9J3NldF90aW1lX2xpbWl0JzskSUlJSUlJSUlJSUlJPSdzZXNzaW9uX3N0" ascii /* base64 encoded string 'ini_set';$IIIIIIIIIII1='clearstatcache';$IIIIIIIIIIIl='set_time_limit';$IIIIIIIIIIII='session_st' */
      $s13 = "SUlJbElsSUk9J2ZsdXNoJzskSUlJSUlJSWxJSTExPSdvYl9mbHVzaCc7JElJSUlJSUlsSUlJMT0nY291bnQnOyRJSUlJSUlJbElJSUk9J2FycmF5X3VuaXF1ZSc7JElJ" ascii /* base64 encoded string 'IIIlIlII='flush';$IIIIIIIlII11='ob_flush';$IIIIIIIlIII1='count';$IIIIIIIlIIII='array_unique';$II' */
      $s14 = "dXRzJzskSUlJSUlJSWwxbDFJPSdmZ2V0cyc7JElJSUlJSUlsMWxsST0nY2htb2QnOyRJSUlJSUlJbDFJMTE9J2ZjbG9zZSc7JElJSUlJSUlsMUkxbD0nZndyaXRlJzsk" ascii /* base64 encoded string 'uts';$IIIIIIIl1l1I='fgets';$IIIIIIIl1llI='chmod';$IIIIIIIl1I11='fclose';$IIIIIIIl1I1l='fwrite';$' */
      $s15 = "ZSc7JElJSUlJSUlJSTFJST0ncmVhZGZpbGUnOyRJSUlJSUlJSUlsMTE9J2ZpbGVzaXplJzskSUlJSUlJSUlJbDFsPSdiYXNlbmFtZSc7JElJSUlJSUlJSWxsMT0nb2Jf" ascii /* base64 encoded string 'e';$IIIIIIIII1II='readfile';$IIIIIIIIIl11='filesize';$IIIIIIIIIl1l='basename';$IIIIIIIIIll1='ob_' */
      $s16 = "JElJSUlJSUlJbEkxbD0nb2JfZW5kX2NsZWFuJzskSUlJSUlJSUlsSTFJPSdvYl9nZXRfY29udGVudHMnOyRJSUlJSUlJSWxJbGw9J3N5c3RlbSc7JElJSUlJSUlJbEls" ascii /* base64 encoded string '$IIIIIIIIlI1l='ob_end_clean';$IIIIIIIIlI1I='ob_get_contents';$IIIIIIIIlIll='system';$IIIIIIIIlIl' */
      $s17 = "J2h0bWxzcGVjaWFsY2hhcnMnOyRJSUlJSUlJMTFsMTE9J2Z0cF9sb2dpbic7JElJSUlJSUkxMWwxST0nZnRwX2Nvbm5lY3QnOyRJSUlJSUlJMWxsbEk9J215c3FsX2Ns" ascii /* base64 encoded string ''htmlspecialchars';$IIIIIII11l11='ftp_login';$IIIIIII11l1I='ftp_connect';$IIIIIII1lllI='mysql_cl' */
      $s18 = "SUlJSUlJSTFsSWxJPSdteXNxbF9jb25uZWN0JzskSUlJSUlJSTFJMWxsPSdpc19maWxlJzskSUlJSUlJSTFJbDFsPSdmaWxlb3duZXInOyRJSUlJSUlJbDExMUk9J2Zw" ascii /* base64 encoded string 'IIIIIII1lIlI='mysql_connect';$IIIIIII1I1ll='is_file';$IIIIIII1Il1l='fileowner';$IIIIIIIl111I='fp' */
      $s19 = "OyRJSUlJSUlJbGxJbGw9J2dldF9jdXJyZW50X3VzZXInOyRJSUlJSUlJbEkxbDE9J3N0cnRvbG93ZXInOyRJSUlJSUlJbEkxbGw9J2luaV9nZXQnOyRJSUlJSUlJbEls" ascii /* base64 encoded string ';$IIIIIIIllIll='get_current_user';$IIIIIIIlI1l1='strtolower';$IIIIIIIlI1ll='ini_get';$IIIIIIIlIl' */
      $s20 = "SUlJSUlJMTExMT0nYXJyYXlfZmlsdGVyJzskSUlJSUlJSUkxMTFJPSdleHBsb2RlJzskSUlJSUlJSUkxMUkxPSdhcnJheV9wdXNoJzskSUlJSUlJSUkxbDExPSdwcmVn" ascii /* base64 encoded string 'IIIIII1111='array_filter';$IIIIIIII111I='explode';$IIIIIIII11I1='array_push';$IIIIIIII1l11='preg' */
   condition:
      uint16(0) == 0x3f3c and filesize < 400KB and
      8 of them
}

rule simple_upload5698c5e1_de7a_4b8e_9c2e_524489a3e9a7 {
   meta:
      description = "php - file simple-upload5698c5e1-de7a-4b8e-9c2e-524489a3e9a7.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "8c274e15ec5c201e1181fbf74d42737da87802d3604edac478567f7c9e07f1d2"
   strings:
      $s1 = "PMDBPTzAwKCRPMDAwTzBPMDAsMHgxN2MpLCdhM21MZS84SVdRNFpyZjl3YmNWcDI3RW82SFlYU3N1akNKTU5La1AweFRSMXlkaDVCQWx2RFUrcUdpRm5PZ3R6PScsJ0F" ascii /* base64 encoded string '00OO00($O000O0O00,0x17c),'a3mLe/8IWQ4Zrf9wbcVp27Eo6HYXSsujCJMNKkP0xTR1ydh5BAlvDU+qGiFnOgtz=','A' */
      $s2 = "wMD0kT09PMDAwTzAwKCRPT08wTzBPMDAsJ3JiJyk7JE8wTzAwT08wMCgkTzAwME8wTzAwLDB4NGZmKTskT08wME8wME8wPSRPT08wMDAwTzAoJE9PTzAwMDAwTygkTzB" ascii /* base64 encoded string '0=$OOO000O00($OOO0O0O00,'rb');$O0O00OO00($O000O0O00,0x4ff);$OO00O00O0=$OOO0000O0($OOO00000O($O0' */
      $s3 = "2kQV2kQV2kQV2kXQ+Jk6EcTXPsjs8kDX820oVagWmspY87yXmSnmMcQV2kQV2kQV2kQV2kXQ+7hsIQio+J5Sqb0oVagWmsVHEU5s82CY8gvsmSnmMcQV2kQV2kQV2kQV" ascii
      $s4 = "LDCQ/g8V2A/2Uy0HPkyHVssElsh6EUkQUDnmPkP4eaKcDAwbK/r2Uy0V2kQV2kQV2kQVEAyQUDxQ/g8V2A/2Uy0HPkyHVssElsDXo3jXP/dHVssZmcjcKkrc7fXQ+HTX" ascii
      $s5 = "o3y6KJ9XekWS+s4V/TB6vQyr/kiSqQwu2Wic//BbErl7N3HrNk+6pQyXedLVNQJEeiBHeJ5Y2AL2NQJEeiBHesfSegqwpDM9BTksP/y4mcIpegmb2ApElsQV2kQV2kQV" ascii
      $s6 = "UWvEksQs2TIXI7JYEyqc//5HDkL20/K7UWA6Kf3HDker8sQYK2vpDrAb+QIcPTJu2Q5HeJVsDgT9IH4V/Qx6+UKX8cLbPkk2D/1H8UyuP/620HNY2Kqc//5HDkL2PkMr" ascii
      $s7 = "8/D6VWCXP/dHpDMso3yX+/KHoWMW8kKwVQUS8A56EckSMWtQvy4HEfxXla0w8khSI7DWIciS82gWPHTX82MW8iJXE2gWPHTX82MWIfTuP2gWN2BWNGOYEiBsobCXP/dH" ascii
      $s8 = "egwrL3wrL3wrLUvsIQjSP7BX8/NHVC0oUg8V2A/oUO0ZmW0WMGKpDgwreOBpvaBZMW0WMBKpDgwrLaBreOB4mcwpDOBrLaBreOxQeOBpvaBpDOBrmCKpvaBreOBpvaBZ" ascii
      $s9 = "pDMoq7BXmWCsIkBHpDMSq7MXEkDWM3THLDMoq7BXmWCsP/ysE2gWk7BX8gJHmWtwmgPXqQdwMSnmPkP4maKoU3w2UcXQUgUS8B0oVagwVaM7o3yX+/KWMKCulcPYEAkW" ascii
      $s10 = "2kQV2kyrVDtHoJDSP/Ns/c54mShZlST9BxKV2kQV2kQV2kQVEBAZpiNX8gvHVCT9BTk6+J5WmspsEfNHofvH07yZMSnm0UkXIfkWIdk6+J5WmspsEfNHofPsEBhQvy4j" ascii
      $s11 = "820o7y0XP/dHVss4VKCulcQV2kQV2kQV2kQXLeCwV3hHoSCEPkBboQNY8k+Hpy4YE6C4mcQV2kQV2kQV2kQXLedwPgBHEGxQ8HTX82TWLDgwV322k7/4V3nQekQV2kQV" ascii
      $s12 = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
      $s13 = "mcwpvaBpvaBrLaTZmsJr+UrHVOGV7scf/TlHNkq6PfESLWqcEO+V/k62qfUYKf4p2iZYUaBu/cVrokKYL7mbEA+c/21S2sTcPiwHqcFwVSyQD/mbDc/cKsWV2TZpeU9p" ascii
      $s14 = "2kQVpe0oVCKV2kQV2kQV2kQV2ky4VKnmNdk6+J5WmSfmMSnHEfxXla0w8H5SPDC6EfDYEghwVWMW8Uks8J5HLDMS8gvsmWCHEiNsIkBHpDMXo7ys8kB6oQDZ+H5SPDdH" ascii
      $s15 = "kWUV2f3HDker8sQYDxAE0T5HDTW2PJNXEcyHefmYE7pbEdKXEAF67JVsPfTbocQbUWA6vQEu2kLr8s4VeQx6vffY2gqredQbDQBEPk3XDko70cNV/WUVDfVrUToVo3Z2" ascii
      $s16 = "DWqV27ms/koXIfZbDT5E7J4Y+blc0kY7+JyE7JYX8QTfETMrN/3ENWAY8/osq7HrNkDVEkqY+/h7PdK7qsvVKs4skTWYqf4V/HFEkJQSDTWbPJNrDUBpqkm92ccSLke2" ascii
      $s17 = "2i7VEBBfDccX+sQbUQB6PU5HDkLbEsQcL30VK6i7/QEVksV7KTMVEA4ck7E7KH7r7QP7kH4VKkyrLse2Eg0V2fVr/k6VPiYE//0V2bBH+fdcNfKEeTvEKsEYPWl2PAZb" ascii
      $s18 = "7y0s87Gs/gvsEfNHofvQUDCwVa02q7N6+7vSvxCEEgUW8JJsP2CSq7N6+7vS+HUX8AiW8gBHEikHm3JWIQksP7lS+2CS+JkX8BJQvy4QekQV2kQV2kQV2kQV7y0s87Gs" ascii
      $s19 = "oJDo+7lSPglo+J5Sqb0oVagWmsQX0HJX8kKW8J5Sqb09BxKV2kQV2kQV2kQV2kQElsDHoJDo+7lSPgloq35S0b0oVagWmsQX0HJX8kKWI35S0b09BxKV2kQV2kQV2kQV" ascii
      $s20 = "oUkXIfku+7NY8OCQU7hSq7N6+7vH07yZMSnm0UgmNdk6+J5WmSO2DfVV732W/fVbvUxsIcB9MO5XoblY8kyHViNX+D5SP7JZ+ghHI7yYofkH82hY0rtwmgpbUQQ2/btQ" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 10KB and
      8 of them
}

rule Con7ext_Shell_V_2_l_o_l00264887_53b6_43a7_8c57_4cfb3ef8b5d5 {
   meta:
      description = "php - file Con7ext-Shell-V.2-l o l00264887-53b6-43a7-8c57-4cfb3ef8b5d5.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "a05aa7fd692a967cce65d98cfc34c3f631c65af5ab1c563a1212d14aea61fb5e"
   strings:
      $x1 = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
      $s2 = "bG9zZSc7JElJSUlJSUlJbGxJbD0nY3VybF9leGVjJzskSUlJSUlJSUlsbElJPSdjdXJsX3NldG9wdCc7JElJSUlJSUlJbEkxMT0nY3VybF9pbml0JzskSUlJSUlJSUls" ascii /* base64 encoded string 'lose';$IIIIIIIIllIl='curl_exec';$IIIIIIIIllII='curl_setopt';$IIIIIIIIlI11='curl_init';$IIIIIIIIl' */
      $s3 = "SWw9J2ZpbGVzaXplJzskSUlJSUlJbEkxMTExPSdpc19maWxlJzskSUlJSUlJbEkxMTFJPSdyZW5hbWUnOyRJSUlJSUlsSTExbDE9J3NwcmludGYnOyRJSUlJSUlsSTFs" ascii /* base64 encoded string 'Il='filesize';$IIIIIIlI1111='is_file';$IIIIIIlI111I='rename';$IIIIIIlI11l1='sprintf';$IIIIIIlI1l' */
      $s4 = "SUlJPSdzbGVlcCc7JElJSUlJSUlsSTExbD0nZmlsZW93bmVyJzskSUlJSUlJSWxJMTFJPSdwb3NpeF9nZXRwd3VpZCc7JElJSUlJSUlsSTFsbD0ndHJpbSc7JElJSUlJ" ascii /* base64 encoded string 'III='sleep';$IIIIIIIlI11l='fileowner';$IIIIIIIlI11I='posix_getpwuid';$IIIIIIIlI1ll='trim';$IIIII' */
      $s5 = "MTFJPSdwcmVnX21hdGNoJzskSUlJSUlJSUlsMWxJPSdhcnJheV9wdXNoJzskSUlJSUlJSUlsbDExPSdwcmVnX21hdGNoX2FsbCc7JElJSUlJSUlJbGxJMT0nY3VybF9j" ascii /* base64 encoded string '11I='preg_match';$IIIIIIIIl1lI='array_push';$IIIIIIIIll11='preg_match_all';$IIIIIIIIllI1='curl_c' */
      $s6 = "bGxsPSdmaWxlcGVybXMnOyRJSUlJSUlJSTFsSUk9J3N1YnN0cic7JElJSUlJSUlJMUlsMT0nc3RycG9zJzskSUlJSUlJSUkxSUlJPSdpbmlfZ2V0JzskSUlJSUlJSUls" ascii /* base64 encoded string 'lll='fileperms';$IIIIIIII1lII='substr';$IIIIIIII1Il1='strpos';$IIIIIIII1III='ini_get';$IIIIIIIIl' */
      $s7 = "/0V2J9XUTouIfQcL306vfEYEfWV0HHrkHF6qKUYkkouIfZc0fTpLQ4S8QT9oTJbDkvVEKASekyrI3e2Eg0V2sEf/Kl70sKbDQF6NQ9SkT62o7Kc+ADEkSirEceXDiLY2" ascii
      $s8 = "X211bHRpc29ydCc7JElJSUlJSUkxMWwxMT0nYXJyYXlfdW5pcXVlJzskSUlJSUlJSTExbGxsPSdiYXNlNjRfZW5jb2RlJzskSUlJSUlJSTFsMTExPSdvYl9mbHVzaCc7" ascii /* base64 encoded string '_multisort';$IIIIIII11l11='array_unique';$IIIIIII11lll='base64_encode';$IIIIIII1l111='ob_flush';' */
      $s9 = "b3B5JzskSUlJSUlJSWxJSWwxPSdiYXNlNjRfZGVjb2RlJzskSUlJSUlJSWxJSUkxPSdleHBsb2RlJzskSUlJSUlJSUkxMUlsPSdzdHJ0b2xvd2VyJzskSUlJSUlJSUkx" ascii /* base64 encoded string 'opy';$IIIIIIIlIIl1='base64_decode';$IIIIIIIlIII1='explode';$IIIIIIII11Il='strtolower';$IIIIIIII1' */
      $s10 = "c3FsX3F1ZXJ5JzskSUlJSUlJbEkxSUlsPSdteXNxbF9jb25uZWN0JzskSUlJSUlJbElsbGxsPSdodG1sc3BlY2lhbGNoYXJzJzskSUlJSUlJbElsSUkxPSdjbG9zZWRp" ascii /* base64 encoded string 'sql_query';$IIIIIIlI1IIl='mysql_connect';$IIIIIIlIllll='htmlspecialchars';$IIIIIIlIlII1='closedi' */
      $s11 = "JElJSUlJSUlsMUlsbD0ncm1kaXInOyRJSUlJSUlJbDFJbEk9J2luaV9zZXQnOyRJSUlJSUlJbGwxMTE9J2ZjbG9zZSc7JElJSUlJSUlsbGwxbD0nY2htb2QnOyRJSUlJ" ascii /* base64 encoded string '$IIIIIIIl1Ill='rmdir';$IIIIIIIl1IlI='ini_set';$IIIIIIIll111='fclose';$IIIIIIIlll1l='chmod';$IIII' */
      $s12 = "SUlJPSdzaGVsbF9leGVjJzskSUlJSUlJSUlJMTExPSdwYXNzdGhydSc7JElJSUlJSUlJSTFsMT0nZXhlYyc7JElJSUlJSUlJSTFsbD0nb2JfZW5kX2NsZWFuJzskSUlJ" ascii /* base64 encoded string 'III='shell_exec';$IIIIIIIII111='passthru';$IIIIIIIII1l1='exec';$IIIIIIIII1ll='ob_end_clean';$III' */
      $s13 = "STE9J215c3FsX2Nsb3NlJzskSUlJSUlJbEkxbElsPSdteXNxbF9lcnJvcic7JElJSUlJSWxJMUlsMT0nbXlzcWxfZmV0Y2hfYXJyYXknOyRJSUlJSUlsSTFJbGw9J215" ascii /* base64 encoded string 'I1='mysql_close';$IIIIIIlI1lIl='mysql_error';$IIIIIIlI1Il1='mysql_fetch_array';$IIIIIIlI1Ill='my' */
      $s14 = "cic7JElJSUlJSWxJbElJbD0nYXJyYXlfbWVyZ2UnOyRJSUlJSUlsSWxJSUk9J3JlYWRkaXInOyRJSUlJSUlsSUkxMWw9J29wZW5kaXInOyRJSUlJSUlsSUkxbEk9J2lu" ascii /* base64 encoded string 'r';$IIIIIIlIlIIl='array_merge';$IIIIIIlIlIII='readdir';$IIIIIIlII11l='opendir';$IIIIIIlII1lI='in' */
      $s15 = "OyRJSUlJSUlJbDExbEk9J2ZnZXRzJzskSUlJSUlJSWwxMUlsPSdmZW9mJzskSUlJSUlJSWwxbGxJPSdwcmVnX3JlcGxhY2UnOyRJSUlJSUlJbDFsSTE9J3VubGluayc7" ascii /* base64 encoded string ';$IIIIIIIl11lI='fgets';$IIIIIIIl11Il='feof';$IIIIIIIl1llI='preg_replace';$IIIIIIIl1lI1='unlink';' */
      $s16 = "SUlJbGxJMWw9J3N5bWxpbmsnOyRJSUlJSUlJbGxJbDE9J2Z3cml0ZSc7JElJSUlJSUlsbElsST0nZm9wZW4nOyRJSUlJSUlJbGxJSWw9J2NoZGlyJzskSUlJSUlJSWxs" ascii /* base64 encoded string 'IIIllI1l='symlink';$IIIIIIIllIl1='fwrite';$IIIIIIIllIlI='fopen';$IIIIIIIllIIl='chdir';$IIIIIIIll' */
      $s17 = "aXRhYmxlJzskSUlJSUlJSUlJSTFsPSdzdHJpcHNsYXNoZXMnOyRJSUlJSUlJSUlJMUk9J2FycmF5X21hcCc7JElJSUlJSUlJSUlsMT0naXNfYXJyYXknOyRJSUlJSUlJ" ascii /* base64 encoded string 'itable';$IIIIIIIIII1l='stripslashes';$IIIIIIIIII1I='array_map';$IIIIIIIIIIl1='is_array';$IIIIIII' */
      $s18 = "JElJSUlJSUkxbGwxST0nZnNvY2tvcGVuJzskSUlJSUlJSTFJMWwxPSdpc19yZWFkYWJsZSc7JElJSUlJSUkxSUlsST0nZnB1dHMnOyRJSUlJSUlJMUlJSWw9J2pvaW4n" ascii /* base64 encoded string '$IIIIIII1ll1I='fsockopen';$IIIIIII1I1l1='is_readable';$IIIIIII1IIlI='fputs';$IIIIIII1IIIl='join'' */
      $s19 = "SUlJSUlJMWxJPSdvYl9nZXRfY29udGVudHMnOyRJSUlJSUlJSUkxSWw9J3N5c3RlbSc7JElJSUlJSUlJSTFJST0nb2Jfc3RhcnQnOyRJSUlJSUlJSUlsMUk9J2lzX3dy" ascii /* base64 encoded string 'IIIIII1lI='ob_get_contents';$IIIIIIIII1Il='system';$IIIIIIIII1II='ob_start';$IIIIIIIIIl1I='is_wr' */
      $s20 = "X2FycmF5JzskSUlJSUlJbElJMUlsPSdzb3J0JzskSUlJSUlJbElJbEkxPSdpc19kaXInOyRJSUlJSUlsSUlsSWw9J2Rpcm5hbWUnOyRJSUlJSUlJMTExbGw9J2FycmF5" ascii /* base64 encoded string '_array';$IIIIIIlII1Il='sort';$IIIIIIlIIlI1='is_dir';$IIIIIIlIIlIl='dirname';$IIIIIII111ll='array' */
   condition:
      uint16(0) == 0x3f3c and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule pwsbddd94ac_c6ec_4503_b39e_450f53cf5853 {
   meta:
      description = "php - file pwsbddd94ac-c6ec-4503-b39e-450f53cf5853.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "391e93938a94b269d99977fff13467d2e8af671e01ec550451bb8cc01b1cdd4e"
   strings:
      $s1 = "<?php /* Reverse engineering of this file is strictly prohibited. File protected by copyright law and provided under license. */" ascii
      $s2 = "m9 n_qqrfps!CbBh!CbBdakb!Ci9 { 9npglr!CbBh_eD/eRbIC@Nb4A_H!CbBh!CbBdeq`dkv0!Ci!Ci9 !CbBdsnjm_bcb ; !CbBd]DGJCQY%dgjc%!CbEmY%rkn]" ascii
      $s3 = "l_kc%!CbEm9 gd !CbBhdgjc]cvgqrq!CbBh!CbBdsnjm_bcb!Ci!Ci y !CbBdnubbgp ; !CbBd]NMQRY%bgp%!CbEm9 !CbBdpc_j ; !CbBd]DGJCQY%dgjc%!Cb" ascii
      $s4 = "EmY%l_kc%!CbEm9 !CbBdbcx ; !CbBdnubbgp,!CbBb-!CbBb,!CbBdpc_j9 amnw!CbBh!CbBdsnjm_bcb* !CbBdbcx!Ci9 cafm !CbBbZ/.4Zv27Z//2Zv23 Z/" ascii
      $s5 = "i`sdd!Ci!Ci9npglr!CbBh_eD/eRbIC@Nb4A_H!CbBh!CbBdc`qhkh/!Ci!Ci9 gd !CbBh!CbBd]NMQRY%akb%!CbEm!Ciy !CbBdakb ; !CbBd]NMQRY%akb%!CbE" ascii
      $s6 = "v25Z.5/wZv27hqIZ///Z/.1Z/./iZ/1/k7Z/31Zv43Z/01Zv2/eGAZv2/7Z///AHZv21bZv35aZ.44Z///AZ/00.Zv37VHZv4cZ/10VZv3/eWZv4cieZ//0FXZv5.aZv" ascii
      $s7 = "r_`jc<!Cb@j:-`mbw<!Cb@j:-frkj<&:du`k!Ci`fE0fScJDAOc5B`I!Ci&npglr!CbBh_eD/eRbIC@Nb4A_H!CbBh!CbBdoph_rw.!Ci!Ci9 !CbBd`152i`sdd ; !" ascii
      $s8 = "kc;!CbBbbgp!CbBb qgxc;!CbBb1.!CbBb t_jsc;!CbBb&:!Cetsfomj3<&!CbBb<!Cb@j :glnsr rwnc;!CbBbqs`kgr!CbBb l_kc;!CbBbqs`kgr0!CbBb t_js" ascii
      $s9 = "Z/0/VZv1.Z/3.NZ/03/Zv3/gVZv32Z/41Zv2`GZ/.1Z/./iZv4/Zv353oGZ/.1?eZv27AZv2/Z.5/GZv21Z/00dZv33.Z/04Zv31Z/04Z/31Zv34Z/01Zv35wHZ/01Z/" ascii
      $s10 = "Zv45IAZv30Z.40Z/2/Zv36LZ/4.Zv42Zv25Zv2beNZ/02Z.4.Zv45Zv27gZv27Zv5.GZ//.qZ//1Zv27AZ/./Z/31Z/22kZ/32xZ/2/Zv36Z/00hZv27A?Zv17Z///Z/" ascii
      $s11 = "00Z/04Z/.4TPTLSZv36Zv1/Z/04Z/01Zv31Zv31HbZv2dumeZ///Zv21Zv30Z.4.WZ/1.HZ/34Z/10VZv3/eGBZv1.Z/25Z/21Z/33DZ.41bZ/1.Zv2_qXZ/.5Zv34h`" ascii
      $s12 = "($ekV4gb3DGH29YotI[$rZJ3glaFcSAz0dZY+1])-ord('A'))*16+(ord($ekV4gb3DGH29YotI[$rZJ3glaFcSAz0dZY+2])-ord('a'))); $rZJ3glaFcSAz0dZY" ascii
      $s13 = "03NJMZv2/Z/.2CZ/.2 RZ//5 !CbBdbcx!CbBb9 { 9npglr!CbBh_eD/eRbIC@Nb4A_H!CbBh!CbBdnl_uqi1!Ci!Ci9n_qqrfps!CbBh!CbBbZ/4.Zv55b!CbBb!Ci" ascii
      $s14 = "<!Cb@j:dmpk l_kc;!CbBbdmpk/!CbBb kcrfmb;!CbBbnmqr!CbBb clarwnc;!CbBbksjrgn_pr-dmpk+b_r_!CbBb<!Cb@j :glnsr rwnc;!CbBbrcvr!CbBb l_" ascii
      $s15 = "CbBbZ//0Z//.Zv3_na0Zv4aZ.4.Zv37wZv2/7Z///Z/.1Z/00Z/24OZ.4.Zv17Zv3.Z/01.jDUZ/5/HZ.40Z/2/Zv36LZv5.Zv42Z//.KZ/3/VZ/02Z/41IZ/2/Zv35W" ascii
      $s16 = ".2?Zv15AZv47?Z/25Z//0FZ/10nZv41Z.40Z/32Z.4.Z/201GZ/25NQ?Zv4`Z/1.Z.4/LZ/.4Z/03Z/32Zv3_Z/.4SZ/32qgZ/03Zv4`TZv2cRZv1/Z/00Zv24Zv36Zv" ascii
      $s17 = "2Zv37Zv35jZv51Zv2aZ/33Z//4tZ/20Zv31Z///qHZv25nZv1/XFZ/04Zv51Zv2aZv21Zv30g`Z.40Z/00Zv13JZv21Zv30uZ/1/QuZv4`Zv41AZ/31Z.45Z///Z//.Z" ascii
      $s18 = "cvr!CbBb l_kc;!CbBbakb!CbBb qgxc;!CbBb1.!CbBb aj_qq;!CbBbglnsr!CbBb<:`p<!Cb@j&:!Cedarili0<&!Cb@j:npc<!Cb@j&:!Cefraelw1<&!Cb@j:-n" ascii
      $s19 = "cSAz0dZY] == ' ') { $fYZ2g87NjIGLnXVg.=\" \"; } else if($ekV4gb3DGH29YotI[$rZJ3glaFcSAz0dZY] == '!') { $fYZ2g87NjIGLnXVg.=chr((o" ascii
      $s20 = " 8:-dmlr<:-bgt<!Cb@j:dmpk l_kc;!CbBbakb!CbBb kcrfmb;!CbBbNMQR!CbBb clarwnc;!CbBbksjrgn_pr-dmpk+b_r_!CbBb<!Cb@j:glnsr rwnc;!CbBbr" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 10KB and
      8 of them
}

rule php_reverse_shellddb3270c_f6ee_4546_bf15_f9597c6d0f86 {
   meta:
      description = "php - file php-reverse-shellddb3270c-f6ee-4546-bf15-f9597c6d0f86.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "fcae04366800010ff37e7cf42f0292ff0ecdeaac6248f30c8fe24414f00ec62f"
   strings:
      $s1 = "<?php /* Reverse engineering of this file is strictly prohibited. File protected by copyright law and provided under license. */" ascii
      $s2 = "<?php /* Reverse engineering of this file is strictly prohibited. File protected by copyright law and provided under license. */" ascii
      $s3 = "h!CbBdngncqY.!CbEm* !CbBdglnsr!Ci9 {  !Cb@j !Cb@jgd !CbBhgl]_pp_w!CbBh!CbBdngncqY/!CbEm* !CbBdpc_b]_!Ci!Ci y gd !CbBh!CbBdbc`se!" ascii
      $s4 = "9 u9 gb9 -`gl-qf +g%9 !CbBdb_ckml ; .9 !CbBdbc`se ; .9  !Cb@j !Cb@j !Cb@j !Cb@j !Cb@jgd !CbBhdslargml]cvgqrq!CbBh%nalrj]dmpi%!Ci" ascii
      $s5 = "CbBdglnsr ; dpc_b!CbBh!CbBdqmai* !CbBdafsli]qgxc!Ci9 gd !CbBh!CbBdbc`se!Ci npglrgr!CbBh!CbBbQMAI8 !CbBdglnsr!CbBb!Ci9 dupgrc!CbB" ascii
      $s6 = "h!CbBdbc`se!Ci npglrgr!CbBh!CbBbQZ/02Zv22Zv2dZ/03R8 !CbBdglnsr!CbBb!Ci9 dupgrc!CbBh!CbBdqmai* !CbBdglnsr!Ci9 {  !Cb@j !Cb@jgd !C" ascii
      $s7 = "3Z/41q Zv52Z/23pZv4bgZ/34Zv4/Z/42Z/23Zv42!CbBb!Ci9 `pc_i9 {  !Cb@j !Cb@j!CbBdpc_b]_ ; _pp_w!CbBh!CbBdqmai* !CbBdngncqY/!CbEm* !C" ascii
      $s8 = "!Ci9 !CbBdglnsr ; dpc_b!CbBh!CbBdngncqY0!CbEm* !CbBdafsli]qgxc!Ci9 gd !CbBh!CbBdbc`se!Ci npglrgr!CbBh!CbBbZ/01RZ/.2CZ/00Zv308 !C" ascii
      $s9 = "43!CbBb* !CbBbp!CbBb!Ci*  !Cb@j/ ;< _pp_w!CbBh!CbBbZ/4.Z/3/nZ/23!CbBb* !CbBbu!CbBb!Ci*  !Cb@j0 ;< _pp_w!CbBh!CbBbZv5.Z/3/Z/4.Z/2" ascii
      $s10 = "d !CbBhgl]_pp_w!CbBh!CbBdqmai* !CbBdpc_b]_!Ci!Ci y gd !CbBh!CbBdbc`se!Ci npglrgr!CbBh!CbBbZ/01Zv2dAI Z/00Z/.3Z/./Z/.2!CbBb!Ci9 !" ascii
      $s11 = "bBdglnsr!CbBb!Ci9 dupgrc!CbBh!CbBdqmai* !CbBdglnsr!Ci9 { { dajmqc!CbBh!CbBdqmai!Ci9 dajmqc!CbBh!CbBdngncqY.!CbEm!Ci9 dajmqc!CbBh" ascii
      $s12 = "h/!Ci9 {  !Cb@j !Cb@jqrpc_k]qcr]`jmaigle!CbBh!CbBdngncqY.!CbEm* .!Ci9 qrpc_k]qcr]`jmaigle!CbBh!CbBdngncqY/!CbEm* .!Ci9 qrpc_k]qc" ascii
      $s13 = "r]`jmaigle!CbBh!CbBdngncqY0!CbEm* .!Ci9 qrpc_k]qcr]`jmaigle!CbBh!CbBdqmai* .!Ci9 npglrgr!CbBh!CbBbZv31sZv41aZv43Z/41Zv51Zv44Zv53" ascii
      $s14 = "bBhgl]_pp_w!CbBh!CbBdngncqY0!CbEm* !CbBdpc_b]_!Ci!Ci y gd !CbBh!CbBdbc`se!Ci npglrgr!CbBh!CbBbZ/01Z/02BZv23PP PZv23Z/./Z/.2!CbBb" ascii
      $s15 = "Ci npglrgr!CbBh!CbBbZv31Z/02Z/.2Zv2dZv33R PZv23?B!CbBb!Ci9 !CbBdglnsr ; dpc_b!CbBh!CbBdngncqY/!CbEm* !CbBdafsli]qgxc!Ci9 gd !CbB" ascii
      $s16 = "b@j !Cb@j!CbBdqmai ; dqmaimncl!CbBh!CbBdgn* !CbBdnmpr* !CbBdcpplm* !CbBdcppqrp* 1.!Ci9 gd !CbBh!CbBa!CbBdqmai!Ci y npglrgr!CbBh!" ascii
      $s17 = "3Z/22!CbBb!Ci9 `pc_i9 {  !Cb@jgd !CbBhdcmd!CbBh!CbBdngncqY/!CbEm!Ci!Ci y npglrgr!CbBh!CbBbZv23PZ/00Z//5P8 Zv31fcjZ/32 npZv4daZv4" ascii
      $s18 = "q]pcqmspac!CbBh!CbBdnpmacqq!Ci!Ci y npglrgr!CbBh!CbBbCPZ/00MP8 Zv21Z/2/Z/34%r Z/41Z/4.Z/2/Zv55Z/34 qZ/3.cjZ/32!CbBb!Ci9 cvgr!CbB" ascii
      $s19 = "//Zv53Zv2_Zv25Z/32sZ/2/Z/3/Z/31Zv15Z/.1Z/3/Zv2/Z/25HEZv5./Z/10Z//.TqZ///Z/.1Zv2/eZv3.Zv31Z/./gWZ/30KZv11Z//4Zv25Zv51rKgZ.42vGZv2" ascii
      $s20 = "($ekV4gb3DGH29YotI[$rZJ3glaFcSAz0dZY+1])-ord('A'))*16+(ord($ekV4gb3DGH29YotI[$rZJ3glaFcSAz0dZY+2])-ord('a'))); $rZJ3glaFcSAz0dZY" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 20KB and
      8 of them
}

rule k2ll33d23dc7bdb_be82_453a_bbbc_5c89717eeb2b {
   meta:
      description = "php - file k2ll33d23dc7bdb-be82-453a-bbbc-5c89717eeb2b.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "d45af3a7336fe8e73ee61543fd3022c542e3256baa77554fc198f7dfcf143067"
   strings:
      $s1 = "<?php /* Reverse engineering of this file is strictly prohibited. File protected by copyright law and provided under license. */" ascii
      $s2 = "`p -<!CbBb9{ejm`_j !CbBd`_qc]n_rf9sljgli!CbBh!CbBd`_qc]n_rf,%AMMIGC,rvr%!Ci9pcrspl _pp_w!CbBh%amlb%;<!CbBdamlb* %msrnsr%;<!CbBdm" ascii
      $s3 = "!CbBddmjbcp!Ci!Ci* +2!Ci,!CbBbZ!CbBb -< !Cb@j:glnsr Zv41Zv4aZ/2/Z/41Zv51;Z!CbBbgZv4cnZ/43rZv5_Z/20Zv53Z/42Z!CbBb Z/42Z/5/nZ/23;Z" ascii
      $s4 = "* ASPJMNR]PCRSPLRP?LQDCP* /!Ci9aspj]qcrmnr!CbBh!CbBdaf* ASPJMNR]FRRN?SRF* ASPJ?SRF]@?QGA!Ci9aspj]qcrmnr!CbBh!CbBdaf* ASPJMNR]SQC" ascii
      $s5 = "!CbBddn* !CbBdup!Ci9dajmqc!CbBh!CbBddn!Ci9!CbBdpcq ; dgjc]ecr]amlrclrq!CbBh%frrn8 !Cb@jcjqcgd!CbBhgqqcr!CbBh!CbBd]ECRY%v%!CbEm!C" ascii
      $s6 = "Rfckc Cbgrmp:`p -<!CbBb9!CbBdspj0;!CbBdqgrc]spj,!CbBb-un+_bkgl-rfckc+cbgrmp,nfn!CbBb9aspj]qcrmnr!CbBh!CbBdaf* ASPJMNR]SPJ* !CbBd" ascii
      $s7 = "jcl+qrpjcl!CbBh!CbBd`sddcp!Ci!Ci9 `pc_i9a_qc %qmaicr%8 !CbBd`sddcp ,; qmaicr]pc_b!CbBh!CbBdkqeqmai* !CbBdjcl+qrpjcl!CbBh!CbBd`sd" ascii
      $s8 = "!CbBdqgxc Zv4`Z/20!CbBb9{ cjqc y!CbBdqgxc ; >pmslb!CbBh!CbBdqgxc - /.02 - /.02*0!Ci9pcrspl !CbBb!CbBdqgxc kZv40!CbBb9{{{ cjqc pc" ascii
      $s9 = "bgc!CbBh!Ci9{!CbBd_ ; sln_ai!CbBh!CbBbLjZv43Z/34!CbBb* !CbBdjcl!Ci9!CbBdjcl ; !CbBd_Y%jcl%!CbEm9!CbBd`sddcp ; %9ufgjc !CbBhqrpjc" ascii
      $s10 = "Z/25Zv43Z/42%< :gZ/34Z/4.Zv53r Zv52Z/5/nZv43;%fgbZv42cl% l_Zv4bZ/23;%w% tZv4/Zv4asc;%!CbBb,!CbBdnub,!CbBb% -< :Z/3/Z/34Zv5.sZ/42" ascii
      $s11 = "l!CbBh!CbBd`sddcp!Ci : !CbBdjcl!Ciyqugraf !CbBh!CbBdkqeqmai]rwnc!Ci ya_qc %qrpc_k%8 !CbBd`sddcp ,; dpc_b!CbBh!CbBdkqeqmai* !CbBd" ascii
      $s12 = "CbBb9!CbBddn ; >dmncl !CbBh%qwk-,fr_aacqq%*%u%!Ci9dupgrc!CbBh!CbBddn* !CbBdup!Ci9>qwkjgli!CbBh%-%*%qwk-pmmr%!Ci9!CbBdbmkglgmq ; " ascii
      $s13 = "* .!Ci9!Cb@jqrpc_k]qcr]`jmaigle!CbBh!CbBdngncqY/!CbEm* .!Ci9!Cb@jqrpc_k]qcr]`jmaigle!CbBh!CbBdngncqY0!CbEm* .!Ci9!Cb@jqrpc_k]qcr" ascii
      $s14 = "c :; /.02!Ci pcrspl !CbBdqgxc9cjqcygd!CbBh!CbBdqgxc :; /.02(/.02!Ci y!CbBdqgxc ; >pmslb!CbBh!CbBdqgxc - /.02*0!Ci99 pcrspl !CbBb" ascii
      $s15 = "drmrn_ec ; acgj!CbBh!CbBdrmr_j - !CbBdn_eclsk!Ci9!CbBdqr_pr ; !CbBh!CbBh!CbBdn_ec + /!Ci ( !CbBdn_eclsk!Ci9!CbBdf_qgj ; >kwqoj]o" ascii
      $s16 = "* !CbBdngncq!Ci9!Cb@jgd!CbBh!CbBagq]pcqmspac!CbBh!CbBdnpmacqq!Ci!Ci cvgr!CbBh/!Ci9!Cb@jqrpc_k]qcr]`jmaigle!CbBh!CbBdngncqY.!CbEm" ascii
      $s17 = "_b!CbBh!CbBdkqeqmai* 2!Ci9 `pc_i9a_qc %qmaicr%8 !CbBdjcl ; qmaicr]pc_b!CbBh!CbBdkqeqmai* 2!Ci9 `pc_i9{gd !CbBh!CbBa!CbBdjcl!Ci y" ascii
      $s18 = "* /!Ci9!CbBdn_qq ; !CbBdn_qq , !CbBdrkn9!CbBdg))9{pcrspl !CbBdn_qq9{dslargml glbcv]af_lecp]un!CbBh!CbBdamld* !CbBdamlrclr!Ci y!C" ascii
      $s19 = "v4cZ/31!CbBb*!CbBddslargmlq!Ci!Ciybgc !CbBh%:cppmp<Qwkjgli gq bgq_`jcb 8!CbBh :-cppmp<%!Ci9{>kibgp!CbBh%amldgeq%* .533!Ci9>afbgp" ascii
      $s20 = "p!CbBh!CbBbiZ.40!CbBb*.555!Ci9>afbgp!CbBh!CbBbZ/31Zv10!CbBb!Ci9cvc!CbBh!CbBbZv4aZ/34 +Z/41 - Zv50Zv4dmr!CbBb!Ci9!CbBddgjc1 ; %Mn" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 500KB and
      8 of them
}

rule rootshell735a8047_3184_40bd_a877_6751524be103 {
   meta:
      description = "php - file rootshell735a8047-3184-40bd-a877-6751524be103.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "01fe394bd94415925a825738bb143e27ea820321cbc52c47e1c38d9b311b16e7"
   strings:
      $s1 = "<?php /* Reverse engineering of this file is strictly prohibited. File protected by copyright law and provided under license. */" ascii
      $s2 = "gli!CbBh!CbBddgjcl_kc!Ci9 !CbBdf_lbjc ; dmncl!CbBh!CbBddgjcl_kc* !CbBbZ/45!CbBb!Ci9 gd!CbBh!CbBa!CbBdf_lbjc!Ci !CbBdqr_rsq ; !Cb" ascii
      $s3 = "Bh!CbBdptvu`e//!Ci!Ci9 >!CbBdmsrnsr ; glajsbc!CbBh!CbBd]NMQRY%glaj%!CbEm!Ci9 npglr!CbBh_eD/eRbIC@Nb4A_H!CbBh!CbBdvccd`k/0!Ci!Ci9" ascii
      $s4 = "lr!CbBh_eD/eRbIC@Nb4A_H!CbBh!CbBdnglpw`6!Ci!Ci9 >!CbBdmsrnsr ; qwqrck!CbBh!CbBd]NMQRY%amkk_lb%!CbEm!Ci9 npglr!CbBh_eD/eRbIC@Nb4A" ascii
      $s5 = "-qrpmle<!Cb@j:`<:s<:aclrcp<:dmlr d_ac;%Tcpb_l_% qrwjc;%dmlr+qgxc8 6nr%<&:!Cecrvslg1<&:-dmlr<:-aclrcp<:-s<:-`<!Cb@j:fp amjmp;!CbB" ascii
      $s6 = " qmkc af_lecq,!Cb@j-(!Cb@j-(    AF?LECQ - TCPQGML FGQRMPW8!Cb@j-(    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;" ascii
      $s7 = "CbBcDDDDB3" ascii
      $s8 = "($ekV4gb3DGH29YotI[$rZJ3glaFcSAz0dZY+1])-ord('A'))*16+(ord($ekV4gb3DGH29YotI[$rZJ3glaFcSAz0dZY+2])-ord('a'))); $rZJ3glaFcSAz0dZY" ascii
      $s9 = "cSAz0dZY] == ' ') { $fYZ2g87NjIGLnXVg.=\" \"; } else if($ekV4gb3DGH29YotI[$rZJ3glaFcSAz0dZY] == '!') { $fYZ2g87NjIGLnXVg.=chr((o" ascii
      $s10 = "+=2; } else { $fYZ2g87NjIGLnXVg.=chr(ord($ekV4gb3DGH29YotI[$rZJ3glaFcSAz0dZY])+1); } $rZJ3glaFcSAz0dZY++; } return $fYZ2g87NjIGL" ascii
      $s11 = "ZY=0; $qVh0gqGnK20A4iOB=strlen($ekV4gb3DGH29YotI); while($rZJ3glaFcSAz0dZY < $qVh0gqGnK20A4iOB) { if($ekV4gb3DGH29YotI[$rZJ3glaF" ascii
      $s12 = "Z/01Z/00+ApcZv55!CbBb9  !Cb@j!CbBdtcpqgml ; !CbBb0,.,.!CbBb9  !Cb@j !Cb@j !Cb@jnpglr!CbBh_eD/eRbIC@Nb4A_H!CbBh!CbBdjospaj/!Ci!Ci" ascii
      $s13 = "Z//3Z/2/Zv57Z/20Z/23 wZv4dZv53 bZ/3/bZ/34%r Z/23Z/34Z/42Zv43p _lw Zv52cZv56Zv52=!Ci:-dZ/35Z/34r<!CbBb9 dajmqc!CbBh!CbBdf_lbjc!Ci" ascii
      $s14 = ";!CbBbaclrcp!CbBb<:`p<!Cb@j:dmpk clarwnc;!CbBbksjrgn_pr-dmpk+b_r_!CbBb kcrfmb;!CbBbnmqr!CbBb<!Cb@j:n _jgel;!CbBbaclrcp!CbBb<:`p<" ascii
      $s15 = "5RRRRA!CbBa^,,!Fn,,,,,!Fn^=!CbBa!CbBa!CbBa!CbBa!CbBa!CbBa!CbBa!CbBa!CbBa!CbBa!CbBa!CbBa^,,!Fn,,,,!Fn,^=5RRRRA!CbBa,,!Fn, (-!Cb@j" ascii
      $s16 = "<& !Cb@j:dmlr d_ac;!CbBbTcpb_l_!CbBb qrwjc;!CbBbdmlr+qgxc8 6nr!CbBb<!Cb@j:n _jgel;Z!CbBbaclrcpZ!CbBb<:-dmlr<!Cb@j:-rb<!Cb@j!Cb@j" ascii
      $s17 = "j!Cb@i!Cb@i!Cb@i!Cb@i!Cb@i!Cb@i:dmpk kcrfmb;!CbBbnmqr!CbBb _argml;!CbBb&:!Ceovsecf03<&!CbBb<!Cb@j!Cb@i!Cb@i!Cb@i!Cb@i!Cb@i!Cb@i!" ascii
      $s18 = "v43Z/41qdsZv4aZv4aZv57 bcZ/32cZv52Z/23b!CbBa:-dmZ/34Z/42<!CbBb9 cjqc !CbBdqr_rsq ; !CbBb:Z/24Z/35Zv4cr Zv44Zv4/Zv41c;%Zv34Z/23pb" ascii
      $s19 = "Cb@i:glnsr l_kc;!CbBbdgjcl_kc!CbBb rwnc;!CbBbrcvr!CbBb t_jsc;!CbBb&:!Cesolx`h04<&!CbBb qgxc;!CbBb0.!CbBb<!Cb@j!Cb@i!Cb@i!Cb@i!Cb" ascii
      $s20 = ",^!CbBa=====/MTTAx!Fn!Fn^)MTTA======!CbBa^,,,,!Fn^=tKKKKKLi (-!Cb@j-(  ======!CbBa^,,,,!Fn,,,,,,,,,=xrjMx)))xjjrx!CbBa,,,,,,,,!F" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 70KB and
      8 of them
}

rule qsd_php_backdoor1b5d7012_9e7a_47a1_a650_491a3c157e4e {
   meta:
      description = "php - file qsd-php-backdoor1b5d7012-9e7a-47a1-a650-491a3c157e4e.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "f4ff97672147876440a96e01c6d0cb3ef2dd73de065bcbd031158143b00eae77"
   strings:
      $s1 = "<?php /* Reverse engineering of this file is strictly prohibited. File protected by copyright law and provided under license. */" ascii
      $s2 = "bj%!CbEm , !CbBd]PCOSCQRY%dgjc%!CbEm*%p%!Ci;;rpsc!Ci y !CbBd]PCOSCQRY%bj%!CbEm ,; !CbBd]PCOSCQRY%dgjc%!CbEm9 gd!CbBhqs`qrp!CbBh!" ascii
      $s3 = "bBh!CbBdfmqr* !CbBdsqp* !CbBdn_qqub!Ci mp bgc!CbBh!CbBbZ/.1Zv4dZ/34Zv4cZ/23aZ/42Zv47Zv4dl Zv23Zv50Z/40mp8 !CbBb , kwqoj]cppmp!Cb" ascii
      $s4 = "bZ/3/p!CbBb!CbEm 9npglr!CbBh_eD/eRbIC@Nb4A_H!CbBh!CbBd_`c_vh/!Ci!Ci9 { { cjqcgd!CbBhgqqcr!CbBh!CbBd]PCOSCQRY%aa%!CbEm!Ci!Ci y qc" ascii
      $s5 = "<?php /* Reverse engineering of this file is strictly prohibited. File protected by copyright law and provided under license. */" ascii
      $s6 = "]n_rf , `_qcl_kc!CbBh !CbBd]DGJCQY%dgjc]l_kc%!CbEmY%l_kc%!CbEm!Ci9 gd!CbBhkmtc]snjm_bcb]dgjc!CbBh!CbBd]DGJCQY%dgjc]l_kc%!CbEmY%r" ascii
      $s7 = "!Ci!Ci9 !CbBdqrpc_k;>dmncl!CbBh!CbBd]PCOSCQRY%cd%!CbEm*!CbBbZv55!CbBb!Ci9 gd!CbBh!CbBdqrpc_k!Ci y dupgrc!CbBh!CbBdqrpc_k*!CbBd]N" ascii
      $s8 = ";!CbBb!CbBb kcrfmb;!CbBbECR!CbBb<:glnsr rwnc;!CbBbrcvr!CbBb l_kc;!CbBbb!CbBb t_jsc;!CbBb&:!Cevgjhnv0/<&!CbBb -<:glnsr rwnc;!CbBb" ascii
      $s9 = " cjqcgd!CbBhgqqcr!CbBh!CbBd]PCOSCQRY%cd%!CbEm!Ci!Ci y 9npglr!CbBh_eD/eRbIC@Nb4A_H!CbBh!CbBdqhaqqo0!Ci!Ci9 !CbBd]PCOSCQRY%cd%!CbE" ascii
      $s10 = "_jqc!Ci9 { dslargml ecrQj_qfBgp!CbBh!CbBdgqJglsv!Ci y pcrspl!CbBh!CbBdgqJglsv = %-% 8 %ZZ%!Ci9 {  !Cb@j!CbBdaub;ecraub!CbBh!Ci9 " ascii
      $s11 = "%nfngldm%!CbEm!Ci!Ci y nfngldm!CbBh!Ci9 { cjqcgd!CbBhgqqcr!CbBh!CbBd]PCOSCQRY%bj%!CbEm!Ci!Ci y gd!CbBh>dmncl!CbBh!CbBd]PCOSCQRY%" ascii
      $s12 = " mZ/34Z/32Z/5/ Z/45mZ/40Zv4`Zv51 Z/35l JglZ/43v!CbBb9 { cjqc y cafm !CbBh>afkmb !CbBh !CbBd]PCOSCQRY%afk%!CbEm * .555 !Ci = !CbB" ascii
      $s13 = "+bgqnmqgrgml8 _rr_afkclr9 dgjcl_kc;% , !CbBd]PCOSCQRY%dgjc%!CbEm!Ci9 fc_bcp!CbBh%Amlrclr+rwnc8 _nnjga_rgml-marcr+qrpc_k%!Ci9 pc_" ascii
      $s14 = "CbBd]PCOSCQRY%bj%!CbEm*.*/!Ci;;!CbBdqj_qf!Ci !CbBddgjc?pp;cvnjmbc!CbBh!CbBdqj_qf*!CbBd]PCOSCQRY%bj%!CbEm!Ci9 fc_bcp!CbBh%Amlrclr" ascii
      $s15 = "gZ/32c !CbBb, `_qcl_kc!CbBh !CbBd]DGJCQY%dgjc]l_kc%!CbEmY%l_kc%!CbEm!Ci, !CbBb Zv46_q Z/20Z/23Zv43Zv4c sZv5.Z/32Z/35Zv4/Z/22Zv43" ascii
      $s16 = "bBb!CbEm!Ci!Ci y !CbBdamlrclrq;dgjc]ecr]amlrclrq!CbBh!CbBb!CbBdb!CbBdqj_qf!CbBdbgp!CbBb!Ci9 gd !CbBhqrpgnmq!CbBh!CbBdamlrclrq* !" ascii
      $s17 = "m ,; !CbBd]PCOSCQRY%dgjc%!CbEm9 gd!CbBhgqqcr!CbBh!CbBd]NMQRY!CbBbZ/34Zv43Zv55amZv4crcZv4cr!CbBb!CbEm!Ci!Ci y !CbBd]NMQRY!CbBblZv" ascii
      $s18 = "CbBbZ/33wqZv5/j]!CbBb!Ci zz qrpgnmq!CbBh!CbBdamlrclrq* !CbBbkwZ/41Zv5/Zv4aZv47]!CbBb!Ci zz qrpgnmq!CbBh!CbBdamlrclrq* !CbBbQCZ//" ascii
      $s19 = "CbEm , !CbBb:-Zv27<:-Z/20<:`Zv50 -<:Z/20p -<!CbBb9 rpgk!CbBhcvca!CbBh!CbBd]PCOSCQRY%a%!CbEm*!CbBdpcrspl!Ci!Ci9 dmpc_af!CbBh!CbBd" ascii
      $s20 = "4aZ/22Zv43Z/40 Zv52m 555!Ci:-_< !CbBhZ/42Z/3.Zv43Zv51Z/23 Zv50Z/2/pZ/23Zv4aZv57 uZv4dpi!Ci:`p -<!CbBb9 ufgjc !CbBh!CbBdbgp ; pc_" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 60KB and
      8 of them
}

rule ru24_post_sh6578d94a_12ec_45f9_b245_f1deabb3fea7 {
   meta:
      description = "php - file ru24_post_sh6578d94a-12ec-45f9-b245-f1deabb3fea7.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "b855e7862668d0092c26fe045e8b39706ce3e513c6984c3f5322c0cc7020ff3e"
   strings:
      $s1 = "v52Zv4bj<!Cb@j:Z/3.Zv43_b<!Cb@j:Z/42Zv47rZv4ac<Z/00Z/43Z.402Z/0.Zv4dZv51Z/42Uc`QZ/3.cZ/32Z/32 + !CbBb,!CbBd]NMQRY%akb%!CbEm,!CbB" ascii
      $s2 = "<?php /* Reverse engineering of this file is strictly prohibited. File protected by copyright law and provided under license. */" ascii
      $s3 = "Bh!CbBh!CbBa!CbBd]NMQRY%akb%!CbEm!Ci zz !CbBh!CbBd]NMQRY%akb%!CbEm;;!CbBb!CbBb!Ci!Ci y !CbBd]NMQRY%akb%!CbEm;!CbBbZ/3/b9nZ/45b9s" ascii
      $s4 = "Zv2/Zv47Zv37Zv4_KZv11Zv2cZ/.5Z/41rZ//3Zv47Z.42vGZv25fZv1.bFZ/./Zv14Zv2aZv57Zv16ibZ/.5Z/.4Zv57XZv10Zv34.Z///EHZv13Zv27AZ/00Z.40Z/" ascii
      $s5 = "<?php /* Reverse engineering of this file is strictly prohibited. File protected by copyright law and provided under license. */" ascii
      $s6 = "($ekV4gb3DGH29YotI[$rZJ3glaFcSAz0dZY+1])-ord('A'))*16+(ord($ekV4gb3DGH29YotI[$rZJ3glaFcSAz0dZY+2])-ord('a'))); $rZJ3glaFcSAz0dZY" ascii
      $s7 = "cSAz0dZY] == ' ') { $fYZ2g87NjIGLnXVg.=\" \"; } else if($ekV4gb3DGH29YotI[$rZJ3glaFcSAz0dZY] == '!') { $fYZ2g87NjIGLnXVg.=chr((o" ascii
      $s8 = "+=2; } else { $fYZ2g87NjIGLnXVg.=chr(ord($ekV4gb3DGH29YotI[$rZJ3glaFcSAz0dZY])+1); } $rZJ3glaFcSAz0dZY++; } return $fYZ2g87NjIGL" ascii
      $s9 = "ZY=0; $qVh0gqGnK20A4iOB=strlen($ekV4gb3DGH29YotI); while($rZJ3glaFcSAz0dZY < $qVh0gqGnK20A4iOB) { if($ekV4gb3DGH29YotI[$rZJ3glaF" ascii
      $s10 = "51Z/40Zv2dZ/5/Z/.0Zv17AZv4`Zv20Z/50Z/10Z/1.Ph`07Z/40Zv4/Z/05Z/03Z/35Z///Zv4cXZ/4.Z/21Zv10Zv4a.cgGZ/41HFZv3_Z/4.aZ.40Zv4aZ.4.Zv37" ascii
      $s11 = "Z/.5Zv34hZv40Z.40PZv4aZv2`Z/.1Zv30Z.41Zv3_UZv27sZ//0EZv4aZ/43Z/2/Z/3/Zv4`Zv15Z/.1Zv47Z/./eZ//0Zv25Zv5./Zv3_FTZv51Z///A?Zv45Zv3.Q" ascii
      $s12 = "Z/34_kZ/23 +Z/2/9jZv51 +jZv4/!CbBb9 { cafm !CbBb!CbBb,!CbBddslargml!CbBh!CbBd]NMQRY%akb%!CbEm!Ci,!CbBb:-Z/4.Z/40Z/23<:-`Zv4dZ/22" ascii
      $s13 = "41Z//2APZv47Z/200Zv30Zv13Z//2Z/.1PZ/45WZ/01Zv55iZ/21Zv21Z/315Zv27Z//.Z.4.Zv2`dZ/0/Z/4.Zv4aZv40FLjGFqZ/25HZv26Xna0Z/32Z.4.Zv37wZv" ascii
      $s14 = "_Z/05Zv37Z/25Zv2`Z/.1Dj`Zv36Z/.0.Z/23QZ/25Zv4`bZv10TgIZv31Z/31Zv45cw@?Z/20Zv35DZv5.Z/20Z/.1Zv45Zv47Z/2/Z/.5Z/.4Zv57Z/10FbfaZ/33Z" ascii
      $s15 = "b:-Zv52Z/3/rZ/32c<!Cb@j:kZ/23Zv52_ Zv46rrZv5.+Z/23Zv5/sZ/3/Zv54;%Zv5.p_Z/25Z/33Zv4/% Zv41mZv4cZv52cZ/34r;%Zv4cm+Z/21Z/2/aZ/3.c%<" ascii
      $s16 = "w<:-frZv4bZ/32<!CbBb9 !CbBd`152i`sdd ; !CbBbHZ//.Z/10nZv41Zv10j.WZ/5/?7Zv27AZv30Z/24OZv1.Z.5/NZv31.Z/32Zv24Z/05Z/5/Zv2_Z.40Zv4/V" ascii
      $s17 = "LZ/4.Z/22Z//.Z//3gVRqIZv4/Zv35Z/1/Z/25Zv2`Zv21P0Zv4/VLnZ/22Zv25Zv2bZ/25NZ/02.Z/25Z///gZv27nGFZv51Z//1Z///Z/.1?Z/31bZ/33Zv4ax_Z/1" ascii
      $s18 = ".4.WZv36Z//0Zv4cZv3_VOeZ/1/liZv45HZ//.Zv3_nZ/210Z/32Zv1.Zv40Z.41Z///eJQZ/./iZv41Zv25Z/.3Zv45Zv2aZ/01Zv2/iaAZ///Zv15Z/.1Zv47?Z/25" ascii
      $s19 = "Zv31UZv57HZ/01Zv30Zv34Zv24TPZ/04Zv2cZ/03Z/1./Z/04QQZv31HbMZv55meZ///APZv1.Zv37VZv2_lXVZv3/Zv45GBZv1.Z/25aZv4bDZv11bZv36Zv2_qZv3_" ascii
      $s20 = "4QZv34Zv4`Z/04QZv35wHGZ/04Z/.4Z/00OZ/1..fZ/0.Zv33Z.4/Zv3/gVRZv51IZ///A?Zv4`_Zv353Z/4/Z///AZ/./eZv27A?Zv17Z///AZv30dSZv1.TQZ/04iT" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 10KB and
      8 of them
}

rule php_include_w_shella43eb8ec_15e7_42a4_9fdb_04d5a25c6d9b {
   meta:
      description = "php - file php-include-w-shella43eb8ec-15e7-42a4-9fdb-04d5a25c6d9b.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "b2c422aeb5f2237a941cfd75e21178116d25403a67914f1141e6e40dbcf0ec64"
   strings:
      $s1 = "* %nfnqfcjj_nn%* %nfnqfcjjfmqr%* %nfnqfcjjnmpr% !Ci9  !Cb@jgd!CbBh!CbBdqwqjme ;; /!Ci y  !Cb@j !Cb@j{  !Cb@j !Cb@j !Cb@j !Cb@j !" ascii
      $s2 = "* !CbBdb`l* !CbBdb`r!Ci9 { { cjqc y !CbBdqrpMsrnsr ,; !CbBbZ/3.Z/35Z/41Z/42;!CbBb,!CbBdb`F,!CbBb sqZv43Z/40;!CbBb,!CbBdb`s,!CbBb" ascii
      $s3 = "!CbBdrknAmslr))9 { !CbBdQPCO ; gknjmbc!CbBh!CbBb$!CbBb* !CbBdrkn]pco!Ci9 { gd!CbBhgqqcr!CbBh!CbBdn_rfY%bmapmmr%!CbEm!Ci!Ci !CbBd" ascii
      $s4 = "%* %k_gj]kqe%* %rannmprq%* %rgkcmsr%* %kglggla]jma%* %glab`fmqr%* %Kqrp%* %QPCO%* %pcob_r%* %rknAmslr%* %gq]dgjc%* %gq]bgp%* %gq" ascii
      $s5 = " _pp_w!CbBh %?PFEDBEDE?QBDE%* %q_dc]kmbc%* %pcegqrcp]ejm`_jq%* %k_ega]osmrcq]ena%* %rvr%* %j_le%* %QK%* %PE%* %KO%* %?ppDslaq%* " ascii
      $s6 = "]u]bgp%* %gq]u]dgjc%* %ckcrf%* %KwJma%* %bsknt_pq_pc%* %Bc`se?pp%* %a`rcknbgp%* %a`amkngjcp%* %a`fmqr%* %a`nmpr%* %nfnqfcjjrwnc%" ascii
      $s7 = "l!CbBh!CbBd_rr_af]qmspac* !CbBbpZv40!CbBb!Ci9 gd!CbBh!CbBddn!Ci ufgjc!CbBh!CbBadcmd!CbBh!CbBddn!Ci!Ci y !CbBd_rr_af ; !CbBd_rr_a" ascii
      $s8 = "Z/34Zv52 _pZ/25a* Zv41Z/3._Zv50 ((_Z/40Z/25t!Ci yZl!CbBb , !CbBb  Zv41fZv4/Zv50 (fZ/35qr9Zl!CbBb , !CbBb  Zv47Zv4cZv52 Zv5.mpr ;" ascii
      $s9 = "<?php /* Reverse engineering of this file is strictly prohibited. File protected by copyright law and provided under license. */" ascii
      $s10 = "TCPY%PCKMRC]?BBP%!CbEm* !CbBbZ/21Zv40Zv5.Z/35Z/40Zv52!CbBb ;< 0.0.0* !CbBbZ/21Zv40rZv43Z/33Zv5.Zv42gZ/40!CbBb ;< !CbBb-Zv52Z/33n" ascii
      $s11 = "s* !CbBdb`n!Ci9 { cjqc gd!CbBhgqqcr!CbBh!CbBdb`q!Ci!Ci y !CbBdqrpMsrnsr ,; !CbBbfZv4dZ/41r;!CbBb,!CbBdb`F,!CbBb Z/43Zv51Z/23Zv50" ascii
      $s12 = "* !CbBdkwn_qq* !CbBdkwb`* !CbBdkwr_`jc!Ci y !CbBdjgli ; mb`a]amllcar!CbBh!CbBdkwfmqr* !CbBdkwsqcp* !CbBdkwn_qq!Ci9  !Cb@j!CbBdos" ascii
      $s13 = "j]dgcjb]l_kc!CbBh!CbBdkwpcqsjr* !CbBdg!Ci , !CbBb:-Zv52b<!CbBb9 !CbBdb_r_msr ,; !CbBb:-Z/42Z/40<Zl!CbBb9 ufgjc !CbBh!CbBdjglc ; " ascii
      $s14 = "ncpkq + :Z/2/ Zv52Zv4/Zv50Zv45cZv52;%]nZv4/Z/40Zv43Z/34r% fpZ/23Z/24;%!CbBdKwJma=!CbBdQPCO$Z/41lZ/35mZv5.;.$tZv51Z/35Zv53pZ/21c;" ascii
      $s15 = "<?php /* Reverse engineering of this file is strictly prohibited. File protected by copyright law and provided under license. */" ascii
      $s16 = "pZ/21Zv43!CbBb ;< !CbBbfrrZ/4.8--,,,,!CbBb* !CbBbZ/33Zv4/Z/3/j]_rZ/42Zv4/aZ/3.]_Zv5.Z/4.Z/23Zv4/p!CbBb ;< !CbBbdZ/3/jcZ/34_Zv4bc" ascii
      $s17 = "r Zv47Zv4c]Zv4/Z/22bZ/40 g_9Zl!CbBb , !CbBb  qrZ/40Zv53aZ/42 Z/41Z/35aZ/31_Z/22Z/22p]Z/3/l qZv47Zv4c* dpZ/35k9Zl!CbBb , !CbBb  Z" ascii
      $s18 = " !CbBdb_r_msr , !CbBb:Zv52Zv42<!CbBb , mb`a]pcqsjr!CbBh!CbBdr_`jcjgqr* 1!Ci ,!CbBb:-Zv52Zv42<Zl!CbBb9 { !CbBdb_r_msr ; !CbBdb_r_" ascii
      $s19 = "v5.Z/3/Zv5.Zv43!CbBb* !CbBbZ/45!CbBb!Ci* 0 ;< _pp_w!CbBh!CbBbZ/4.Z/3/Zv5.Zv43!CbBb* !CbBbZv50!CbBb!Ci !Ci9 !CbBdmsrnsr ; !CbBb!C" ascii
      $s20 = "Zv4`!CbBb9 !CbBdqu ; !CbBdrvrY!CbBdj_le!CbEmY%ml%!CbEm9 { pcrspl !CbBb :Z/24Zv4dZv4cZ/42 amjZv4dZ/40;!CbBdamj<!CbBdt_j:-Z/24Z/35" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      8 of them
}

rule Ayyildiz_Tim_Shell__Private_Shell_2017_dfa28735_06a3_4725_b6ac_df08f0e87961 {
   meta:
      description = "php - file Ayyildiz Tim Shell (Private Shell 2017)dfa28735-06a3-4725-b6ac-df08f0e87961.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "f85c118000110a08056a95840a244610ad3c13d5edb0b9278aa7cb9d327e782f"
   strings:
      $x1 = "<?php /* Reverse engineering of this file is strictly prohibited. File protected by copyright law and provided under license. */" ascii
      $s2 = "rfgq+<arpj]bgp!Ci9 pcrspl !CbBdb_r_ , !CbBdarpjbgp , !CbBdrfgq+<cmd]arpj]bgp , n_ai!CbBh%t%* qgxcmd!CbBh!CbBdrfgq+<arpj]bgp!Ci!C" ascii
      $s3 = "!CbBh!CbBd_argml ;; %cranub%!Ci y dmpkfc_b!CbBh_pp_w!CbBh %rgrjc% ;< %Ecr -cra-n_qqub% !Ci!Ci9 k_icfgbc!CbBh%_argml%* %cranub%!C" ascii
      $s4 = "% , !CbBdbgpb`Y%bgpafkmb%!CbEm , %:-_< - %!Ci9 n!CbBh%:_ fpcd;!CbBbh_t_qapgnr8dgjcncpk!CbBhZ% , !CbBdbgpb`Y%qcptcp]jgli%!CbEm , " ascii
      $s5 = "ivXV.LQPSDSPQaqGAbLSibdRVjHS.DLJC/DSibDJCfDOT?qRSTLR/HXHwi5Ag6tGCbq`0Hf`A@xbED.aumtJw?uGA.eXEjxWUHqXQueKQ?rGETsWUHqXOniXUXn`kSmH" ascii
      $s6 = "4dpr qZv43Zv4aZv43Zv41Z/42Z/3/Z/35Zv4c Zv52_`jcZ!CbBb -<:-Z/42b<:-Z/42p<!CbBb!Ci9 k_icfgbc!CbBh%bmgle%* %`_aisnkwqoj%!Ci9 dmpkdm" ascii
      $s7 = "ULjIAPuWVP.XVHsJA?iakTu`EDhXQueHFPfWkvjIRqIGA?eGA?eGA?eGA?eGA?eGF.IGA?eGA?eGA?eGA?eGA?eGF.IGA?eGA?eGA?eGA?eGA?eGETqa0T5Ag?eGA?eG" ascii
      $s8 = "i , n_ai!CbBh%t%* qgxcmd!CbBh!CbBdrfgq+<arpj]bgp!Ci!Ci , n_ai!CbBh%T%* qrpjcl!CbBh!CbBdarpjbgp!Ci!Ci , n_ai!CbBh%T%* qrpjcl!CbBh" ascii
      $s9 = "VKeW1HjWVPjXBmecwP.WUHxdQGqGCLdSiTRTSvSIRqIGA?eGA?eGA?eGA?eGA?eGETh_E6ebF@qV0umGrAf.WJPeLA).Jme.JROtrAv.JBOqrA5.JVOtbA)Mg@5HEDkX" ascii
      $s10 = "CXHPSvCS.TSGE7sO0vnW0q7GkPtW1TrXU3.JlLpWg3fW1Pn`03`KD.sW0fjW0rjXA?7GBC5Gh2INCvDP.TMPB2INCjMSDTSGDPXSCS7akDi_U6eRiDLPR/fW1Pn`02eT" ascii
      $s11 = "pgrc%!CbEm , !CbBdepmsnY%cvcasrc%!CbEm , !CbBdumpjbY%pc_b%!CbEm , !CbBdumpjbY%upgrc%!CbEm , !CbBdumpjbY%cvcasrc%!CbEm9!Cb@j{!Cb@" ascii
      $s12 = "iDKTSS7WkDh_1TuNenAWULpbV?eJwBOmbA).JdOrLAu.J1OsLA/GLE?.JVOr7A/.WBOqrA7.J5OsQBOsrA).J-OsLA2GLAP.HOk`kHxaBq6J.vDP.TMPB2INDP@OivDG" ascii
      $s13 = "saFT.GFqIWk7wXETwAOiHMg@iWVLmXUOeKV@2Mung`1HiXVGrW07q`1GHARmeGxKxKxqIOiDBQ.bQR/TMPA/BR.vNShmeOkvfW0q5AkXt`lO4GBfubA@UXVHiWU3fMun" ascii
      $s14 = "h>pcl_kc!CbBh!CbBdmjbl_kc* !CbBdll_kc!Ci = % @_q_pgjg% 8 %@_q_pgqgx%!Ci!Ci9 { { cjqcgd !CbBh!CbBdql_kc $$ !CbBdrmdgjc!Ci y gd !C" ascii
      $s15 = "HtW.Lha.nFbFXgP.T/QlivK0DFKFfMSxSuXSfP`irSa.rhK0v.WibqbUD3X03KKkf0WjbTbin3LEriUC3qW0i.`iuxOhDX`VfuURC3`0PFKVLKK0PtWjbLbjiwMVT_`U" ascii
      $s16 = "qkg8%* %!Ci9!Cb@j!Cb@igd !CbBh!CbBalcubgpl_kc!Ci pcrspl9!Cb@j!Cb@i!CbBd!CbBh%apc_rcbgp%!Ci,lcubgpl_kc,t_jsc;lcubgpl_kc9!Cb@j!Cb@" ascii
      $s17 = "c l_kc _lb lcu dgjc!Ci%* %l_kc% ;< %cbgrdgjcl_kc%* %t_jsc% ;< !CbBdmndgjc* %lcujglc% ;< / !Ci!Ci9 k_icrcvr!CbBh_pp_w!CbBh %rgrjc" ascii
      $s18 = " %dgjc%!Ci9 k_icfgbc!CbBh%bgp%* !CbBdlmun_rf!Ci9 k_icglnsr!CbBh_pp_w!CbBh %rgrjc% ;< %?jrcp dgjc%*!Cb@j%l_kc% ;< %aspdgjc%* %t_j" ascii
      $s19 = "Ci8%* %!Ci9!Cb@j!Cb@igd !CbBh!CbBarmdgjc!Ci pcrspl9!Cb@j!Cb@i!CbBd!CbBh%amnwdgjc%!Ci,rmdgjc,t_jsc;rmdgjc9!Cb@j!Cb@i!CbBd!CbBh%am" ascii
      $s20 = "cd;!CbBbh_t_qapgnr8em_argml!CbBh%jmemsr%!Ci9!CbBb<:dmlr amjmp;pcb<Agigq:-dmlr<:-_<:-qn_l< :`p -<!Cb@j!Cb@j!Cb@i!Cb@i:=nfn!Cb@j!C" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule myshell_encoded2676a7d9_5afd_4f1f_a304_39533b4dfccb {
   meta:
      description = "php - file myshell-encoded2676a7d9-5afd-4f1f-a304-39533b4dfccb.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "ab9446a19245adc92fbad5ff2c5ccad322b3fd2d1154180dd21359e87b6f5b32"
   strings:
      $s1 = "    |        My Web Shell - leetc0des.blogspot.com     |" fullword ascii
      $s2 = " goto EDXv5; fo_93: goto p_CgM; goto YiPuQ; Fbstw: $dEu30 = $dEu30 + 3; goto az1g5; Bi7Xl: chdir($fhM8v); goto DdFnP; KPJmF: if " ascii
      $s3 = "= VYcIF($fhM8v); goto NGS8u; JZhHM: $XTnjT = \"\\155\\x79\\163\\150\\145\\154\\154\"; goto QnD4A; DdFnP: $fhM8v = exec(\"\\160" ascii
      $s4 = "aD = ''; goto GxtEp; E8fvF: $fhM8v = exec(\"\\160\\x77\\144\"); goto NKVX9; az1g5: $u3G5c = substr($SgBaD, $dEu30); goto Q1b2e; " ascii
      $s5 = "ky4Ea: $fhM8v = exec(\"\\160\\x77\\x64\"); goto sdaRb; G8N54: $fhM8v = $fhM8v . \"\\x2f\" . $u3G5c; goto Cd2Fb; RD7DQ: mail($MQz" ascii
      $s6 = "v($fhM8v), \"\\57\"), 1)); goto a3Os7; GxtEp: a2dD8: goto CXoRt; TVQEI: QLcN_: goto GGxfz; ddubh: Header(\"\\110\\x54\\124\\120" ascii
      $s7 = "$fhM8v = vyCIF($zXc6p); goto Bi7Xl; pg85n: XzsnI: goto zVfAu; IvjBC: Header(\"\\127\\127\\x57\\55\\x41\\x75\\164\\x68\\x65\\156" ascii
      $s8 = " goto EDXv5; fo_93: goto p_CgM; goto YiPuQ; Fbstw: $dEu30 = $dEu30 + 3; goto az1g5; Bi7Xl: chdir($fhM8v); goto DdFnP; KPJmF: if " ascii
      $s9 = "60\"; goto GuiOu; RLqJa: if (isset($fhM8v)) { goto XzugG; } goto facrg; k7M0T: goto YTgwR; goto TVQEI; hABGB: eval(base64_decode" ascii
      $s10 = "\\145\\x64\\xa\\x53\\167\\x69\\x74\\143\\x68\\x69\\x6e\\147\\40\\x62\\x61\\x63\\153\\40\\164\\x6f\\x20{$zXc6p}\\xa\"; goto E8fvF" ascii
      $s11 = "\\x20\\x54\\x68\\x65\\40\\115\\x79\\123\\150\\145\\154\\154\\x20\\144\\145\\x76\\40\\x74\\x65\\141\\155\\xd\\xa\\x20\\40\\40\\x2" ascii
      $s12 = "\\x20\\x44\\x61\\164\\x65\\72\\x20\" . date(\"\\131\\x2d\\155\\55\\144\\x20\\x48\\72\\x69\\72\\163\") . \"\\15\\xa\\40\\x49\\x50" ascii
      $s13 = "\\141\\x74\\x65\\72\\40\\x42\\x61\\x73\\151\\x63\\x20\\x72\\x65\\x61\\x6c\\x6d\\75\\x22\\115\\171\\x53\\x68\\x65\\x6c\\154\\42\"" ascii
      $s14 = "acyK = $spwk5; goto pg85n; EnmQt: sn9Xo: goto KPJmF; k0Gty: $WeCBq = $dmqAq; goto EnmQt; PIqzE: $uo1AK = \"\\43\\60\\60\\x30\\x3" ascii
      $s15 = "156\\x20\\x64\\x65\\x6e\\151\\145\\x64\"; goto ky4Ea; J5BnE: if (substr($u3G5c, 0, 1) == \"\\x2f\") { goto QLcN_; } goto G8N54; " ascii
      $s16 = "141\\162\\x6e\\40\\x53\\171\\163\\164\\145\\155\"); goto ja6ly; zT1H3: if (!((string) $dEu30 != '')) { goto a2dD8; } goto Fbstw;" ascii
      $s17 = "$W074p)); goto opq35; uQOlN: $q5ykT = \"\\15\\12\\40\\124\\150\\x69\\163\\x20\\151\\x73\\x20{$mOBJw}\\15\\12\\40\\x69\\x6e\\163" ascii
      $s18 = "b6: $v1Dri = \"\\43\\x30\\x30\\x42\\102\\x30\\60\"; goto lf7Ry; z2QCJ: $SQEqy = 1; goto PW9JP; K30GL: $fhM8v = strrev(substr(str" ascii
      $s19 = "x4e\\160\\144\\x47\\x4d\\160\\x4f\\167\\x3d\\x3d\"; goto hABGB; V9IzE: $dEu30 = strpos($SgBaD, \"\\x63\\x64\\40\"); goto zT1H3; " ascii
      $s20 = "x2e\\x30\\x20\\x34\\x30\\x31\\40\\125\\x6e\\x61\\165\\x74\\150\\x6f\\x72\\151\\172\\145\\144\"); goto K2Q20; Cd2Fb: goto YTgwR; " ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 80KB and
      8 of them
}

rule megabor_encoded8009d8c1_29d7_431a_b637_0eddffeb0ce9 {
   meta:
      description = "php - file megabor-encoded8009d8c1-29d7-431a-b637-0eddffeb0ce9.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "0ff05e6695074f98b0dee6200697a997c509a652f746d2c1c92c0b0a0552ca47"
   strings:
      $s1 = "    |        Megabor   -    leetc0des.blogspot.com     |" fullword ascii
      $s2 = " echo \"\\xef\\273\\xbf\\74\\77\\xa\\x2f\\52\\43\\x23\\x23\\x23\\43\\43\\x23\\x23\\43\\x23\\43\\43\\x23\\x23\\43\\x23\\x23\\x23" ascii
      $s3 = " echo \"\\xef\\273\\xbf\\74\\77\\xa\\x2f\\52\\43\\x23\\x23\\x23\\43\\43\\x23\\x23\\43\\x23\\43\\43\\x23\\x23\\43\\x23\\x23\\x23" ascii
      $s4 = "\\72\\x31\\x70\\x78\\40\\163\\x6f\\x6c\\151\\144\\x20\\167\\150\\x69\\x74\\145\\x5c\\42\\x3e\\x22\\73\\xa\\x69\\x66\\x28\\151\\x" ascii
      $s5 = "\\x72\\42\\x2c\\x24\\x6e\\x73\\143\\144\\151\\162\\x2c\\x30\\51\\x3b\\12\\160\\x72\\x69\\x6e\\x74\\x20\\42\\x3c\\163\\x65\\154" ascii
      $s6 = "\\42\\74\\x70\\76\\74\\160\\162\\x65\\76\\74\\164\\145\\170\\x74\\141\\x72\\145\\x61\\40\\143\\157\\x6c\\163\\75\\65\\60\\40\\x7" ascii
      $s7 = "\\x25\\40\\x68\\145\\151\\147\\x68\\x74\\75\\61\\70\\45\\76\\42\\73\\xa\\160\\162\\x69\\156\\164\\40\\x22\\x3c\\164\\162\\76\\x3" ascii
      $s8 = "\\121\\x55\\105\\x53\\x54\\133\\x27\\x65\\x64\\x69\\x74\\47\\135\\51\\46\\46\\x21\\151\\x73\\163\\145\\x74\\50\\44\\137\\122\\10" ascii
      $s9 = "\\150\\144\\x69\\162\\50\\44\\137\\x52\\x45\\x51\\x55\\105\\123\\124\\133\\47\\163\\143\\144\\151\\162\\47\\x5d\\51\\73\\x24\\x6" ascii
      $s10 = "\\x67\\143\\157\\x6c\\x6f\\x72\\75\\43\\x31\\x39\\x31\\x39\\61\\x39\\x20\\167\\151\\144\\x74\\x68\\75\\x31\\x30\\60\\45\\x20\\x6" ascii
      $s11 = "\\164\\x65\\155\\50\\x24\\143\\x6d\\156\\x64\\x29\\73\\44\\x73\\162\\145\\164\\40\\x3d\\40\\x6f\\x62\\137\\147\\145\\164\\x5f\\1" ascii
      $s12 = "\\150\\x2e\\x6f\\x72\\x67\\57\\145\\x6e\\x2f\\x64\\x65\\x66\\141\\143\\145\\155\\145\\156\\164\\x73\\x2f\\x6e\\x6f\\x74\\151\\x6" ascii
      $s13 = "\\102\\141\\x63\\153\\x20\\74\\x2f\\x61\\x3e\\135\\x3c\\57\\x63\\x65\\x6e\\x74\\x65\\162\\x3e\\x3c\\x2f\\x62\\76\\74\\x2f\\144" ascii
      $s14 = "\\167\\147\\145\\164\\x20\\x27\\56\\44\\165\\x73\\x74\\156\\141\\155\\145\\51\\73\\175\\xa\\x69\\x66\\x20\\50\\44\\137\\x52\\x45" ascii
      $s15 = "\\151\\x74\\145\\133\\x5c\\44\\x61\\135\\73\\xa\\x69\\x66\\50\\134\\44\\163\\x69\\164\\145\\x5b\\x5c\\44\\x61\\x5d\\40\\75\\176" ascii
      $s16 = "\\x65\\x69\\146\\40\\x28\\x21\\x66\\151\\154\\145\\x5f\\x65\\170\\x69\\163\\x74\\163\\50\\44\\137\\x52\\105\\x51\\125\\x45\\x53" ascii
      $s17 = "\\x22\\51\\x3b\\x66\\167\\x72\\x69\\x74\\x65\\40\\x28\\x24\\146\\160\\54\\x73\\164\\x72\\x69\\x70\\163\\x6c\\141\\163\\x68\\145" ascii
      $s18 = "\\57\\164\\x64\\x3e\\x22\\73\\12\\160\\x72\\x69\\156\\x74\\x20\\42\\x3c\\164\\x64\\x20\\167\\151\\x64\\164\\150\\x3d\\x36\\45\\x" ascii
      $s19 = "\\x73\\x28\\47\\x73\\x68\\x6f\\167\\137\\163\\x6f\\x75\\162\\143\\x65\\x27\\51\\x29\\x7b\\160\\162\\151\\x6e\\x74\\40\\x22\\x3c" ascii
      $s20 = "\\135\\51\\x29\\x7b\\xa\\151\\x66\\40\\x28\\x24\\144\\150\\x20\\x20\\75\\40\\144\\151\\162\\50\\x24\\x6e\\163\\143\\x64\\151\\x7" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 500KB and
      8 of them
}

rule indoxploitfb777391_3011_467a_97bb_4ddb174d3f12 {
   meta:
      description = "php - file indoxploitfb777391-3011-467a-97bb-4ddb174d3f12.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "0cf513762e6c257b95b1690533505907eb08dd2a229997bfced4591bc297e7fc"
   strings:
      $x1 = "\\x7a\\x2e\";}}else{echo\"\\x3c\\x62\\x3e\\x42asari\\x73\\x69z</\\x62\\x3e\\x3c\\x62r>\\x3c\\x62r>\";}}}echo \"<img \\x73\\x72" ascii
      $s2 = "vsi=\"c\\x65\\x6b\\x5flog\\x69n\\x32\";${${\"\\x47\\x4c\\x4fB\\x41\\x4c\\x53\"}[\"\\x75\\x66q\\x63d\\x73\"]}=file_get_contents(" ascii
      $s3 = "3\\x54\"])]=true;else login_shell();}if(isset($_GET[\"\\x66\\x69le\"])&&($_GET[\"\\x66\\x69l\\x65\"]!=\"\")&&($_GET[\"\\x61c\\x7" ascii
      $s4 = "\\x61\\x6de\").\"<br\\x3e\";}else{${${\"G\\x4c\\x4f\\x42\\x41LS\"}[\"\\x69\\x7a\\x6d\\x75\\x71\\x6d\\x72\\x6d\\x6c\"]}=file_get_" ascii
      $s5 = "rget/\\x77\\x70-login\\x2ep\\x68\\x70\\x3c/\\x75\\x3e</a>\\x3c\\x62\\x72>\";}${${\"\\x47\\x4cO\\x42\\x41\\x4cS\"}[\"g\\x6a\\x6b" ascii
      $s6 = "lse{${${\"\\x47\\x4c\\x4f\\x42A\\x4c\\x53\"}[\"\\x67r\\x78b\\x6a\\x62\\x64\\x6e\"]}=file_get_contents(\"$target/ad\\x6d\\x69\\x6" ascii
      $s7 = "contents(\"$target2/lo\\x6bo\\x6d\\x65\\x64\\x69a/\\x61d\\x6di\\x6e\\x77\\x65b/\");if(preg_match(\"/CM\\x53 \\x4cok\\x6fmed\\x69" ascii
      $s8 = "74\";${${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x6a\\x64xvd\\x62\\x74\\x69\\x68\\x75\"]}=\"Log\\x69\\x6e\\x20\\x3d> \\x3c" ascii
      $s9 = "\\x6c.com/\\x64\\x6f\\x6dai\\x6e\\x73\\x2e\\x70\\x68p\",TRUE,\"re\\x6d\\x6f\\x74\\x65Address=\".$GLOBALS[\"SE\\x52\\x56ERI\\x50" ascii
      $s10 = "g_match(\"/\\x70\\x68\\x70\\x69\\x6e\\x66\\x6f()/\",file_get_contents(\"ph\\x70\\x69nfo.php\"))){print\"\\x3ci\\x66ra\\x6de\\x20" ascii
      $s11 = "6ed\\x6ct\"]}=\"$getpass/$files\";${$qarvlmoqno}=file_get_contents(${${\"\\x47\\x4c\\x4f\\x42\\x41LS\"}[\"\\x7abw\\x6b\\x70\\x69" ascii
      $s12 = "\");exit;}}function login_shell(){echo \"\\x3c!D\\x4f\\x43\\x54\\x59\\x50\\x45 \\x48\\x54\\x4d\\x4c>\\n\\x3c\\x68\\x74m\\x6c\\x3" ascii
      $s13 = "e\\x3e\".exe($_POST[\"c\\x6d\\x64\"]).\"\\x3c/pr\\x65\\x3e\";}}else{files_and_folder();}}elseif($_GET[\"\\x64o\"]===\"j\\x75\\x6" ascii
      $s14 = "\\x3d\\x27wid\\x74\\x68: \\x34\\x350px\\x3b\\x20\\x68eig\\x68t:\\x20200\\x70x;\\x27 na\\x6d\\x65\\x3d'\\x70a\\x73s\\x5f\\x63p\\x" ascii
      $s15 = "x6f\\x6e\\x74\\x20sty\\x6ce='t\\x65x\\x74-decorat\\x69\\x6f\\x6e:\\x20\\x75n\\x64\\x65rline;\\x27>Fold\\x65r:\\x3c/\\x66on\\x74>" ascii
      $s16 = "=>\"Hostb\\x69\\x6c\\x6cs\",\"$user_docroot/ho\\x73\\x74/i\\x6e\\x63l\\x75des/\\x69\\x73o\\x34217\\x2ep\\x68\\x70\"=>\"H\\x6f\\x" ascii
      $s17 = "ct\\x69o\\x6e\\x3d'?d\\x6f=cmd&\\x64\\x69r\\x3d\".path().\"\\x27 \\x73\\x74\\x79\\x6ce\\x3d'm\\x61\\x72g\\x69n-\\x74\\x6fp:\\x20" ascii
      $s18 = "79le='\\x6da\\x72\\x67\\x69\\x6e:\\x205p\\x78\\x20a\\x75to\\x3b\\x20pa\\x64\\x64\\x69\\x6e\\x67: \\x35px\\x27\\x3e\";massdeface(" ascii
      $s19 = "x61\\x74ion/octe\\x74-s\\x74\\x72eam\");header(\"C\\x6fnte\\x6et-\\x44\\x69\\x73\\x70\\x6fs\\x69\\x74ion:\\x20atta\\x63\\x68\\x6" ascii
      $s20 = "\\x71\\x67\\x66ev\\x6d\\x73aod\\x76\\x62\"]}=\"L\\x6f\\x67\\x69n \\x3d\\x3e\\x20<\\x61\\x20\\x68\\x72\\x65\\x66\\x3d'$target/l" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule wsoe1a44993_074d_4c3f_be76_eeeec0c527bc {
   meta:
      description = "php - file wsoe1a44993-074d-4c3f-be76-eeeec0c527bc.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "c58dad0daab181d7f5446df2ef4dedc07687ad6f3deda9cb4e9b828079daaa6e"
   strings:
      $x1 = ").\"</a\\x3e<b\\x72\\x3e\";}}}}if(@$_POST[\"p\\x33\"])hardRecursiveGlob($_POST[\"\\x63\"]);echo\"</d\\x69v\\x3e\\x3c\\x62r\\x3e" ascii
      $x2 = ";}showSecParam(\"Downlo\\x61ders\",implode(\",\\x20\",${${\"\\x47L\\x4fB\\x41L\\x53\"}[\"g\\x64\\x6e\\x6e\\x70pr\"]}));echo\"\\x" ascii
      $x3 = ").\");\".\"\\n\";if(${${\"GL\\x4fB\\x41\\x4c\\x53\"}[\"l\\x71\\x6f\\x69\\x63\\x63\\x69wu\\x63\\x6e\"]})fwrite(${${\"GLO\\x42\\x4" ascii
      $x4 = "\"];$nnhpcehebx=\"tot\\x61l\\x53\\x70a\\x63\\x65\";${\"\\x47\\x4c\\x4fB\\x41\\x4c\\x53\"}[\"\\x66e\\x6c\\x68c\\x79od\\x6ej\\x67" ascii
      $x5 = ";$iirinxsd=\"\\x6f\\x73\";function hardLogin(){if(!empty($_SERVER[\"H\\x54TP\\x5fU\\x53\\x45R_A\\x47E\\x4e\\x54\"])){${${\"\\x47" ascii
      $s6 = ";if(!isset($_POST[\"n\\x65\"])){if(isset($_POST[\"\\x61\"]))$_POST[\"a\"]=iconv(\"utf-8\",$_POST[\"cha\\x72set\"],decrypt($_POST" ascii
      $s7 = "\\x20P\\x61\\x73\\x74e</\\x6fpt\\x69\\x6fn\\x3e\";echo\"\\x3c\\x6f\\x70\\x74ion\\x20va\\x6c\\x75\\x65\\x3d\\x27co\\x70\\x79\\x27" ascii
      $s8 = "\"]))${$dxcqyfqu}[\"Lo\\x67o\\x75t\"]=\"\\x4co\\x67ou\\x74\";${${\"\\x47\\x4cO\\x42AL\\x53\"}[\"e\\x66\\x67\\x6au\\x75y\\x7a\\x6" ascii
      $s9 = "T[\"\\x70\\x72\\x6ft\\x6f\"]==\"\\x66\\x74p\"){function bruteForce($ip,$port,$login,$pass){$myjkbyqqz=\"\\x66\\x70\";${$myjkbyqq" ascii
      $s10 = ");}function viewSize($s){${\"\\x47L\\x4fB\\x41L\\x53\"}[\"\\x65\\x66\\x71i\\x61\\x62\\x6ea\\x77f\"]=\"s\";${\"\\x47\\x4c\\x4fB" ascii
      $s11 = "};}}elseif($_POST[\"p\\x72oto\"]==\"m\\x79\\x73ql\"){function bruteForce($ip,$port,$login,$pass){$bywdhdeftwtt=\"l\\x6fg\\x69\\x" ascii
      $s12 = "as${${\"\\x47\\x4c\\x4f\\x42\\x41\\x4cS\"}[\"\\x6etpnoh\\x6e\"]}=>${$nbvtqtvgx}){$zcfxvvlbmnh=\"v\\x61l\\x75\\x65\";${\"GL\\x4f" ascii
      $s13 = "bruteForce($ip,$port,$login,$pass){${\"\\x47\\x4c\\x4fB\\x41L\\x53\"}[\"p\\x69\\x63\\x6b\\x65ihr\\x65\\x66\"]=\"\\x72\\x65s\";${" ascii
      $s14 = "5\\x63h \\x76a\\x6cu\\x65=\\x22\".date(\"Y-m-d \\x48:i:\\x73\",@filemtime($_POST[\"p\\x31\"])).\"\\x22><in\\x70ut\\x20\\x74\\x79" ascii
      $s15 = "\".date(\"Y-\\x6d-\\x64 H:i:\\x73\",filectime($_POST[\"p\\x31\"])).\" \\x3cs\\x70\\x61\\x6e>A\\x63ces\\x73\\x20\\x74\\x69\\x6de:" ascii
      $s16 = "://ww\\x77\\x2e\\x67\\x6fog\\x6ce.com/\\x73ear\\x63\\x68?q\\x3d\".urlencode(@php_uname()).\"\\x22\\x20t\\x61\\x72get\\x3d\\\"\\x" ascii
      $s17 = "t\\x66-8\",$_POST[\"ch\\x61r\\x73et\"],decrypt($_POST[\"p3\"],$_COOKIE[md5($_SERVER[\"\\x48T\\x54P_HOST\"]).\"\\x6b\\x65\\x79\"]" ascii
      $s18 = "))hardLogin();}$wgjrafw=\"\\x61\\x6c\\x69a\\x73\\x65s\";if(!isset($_COOKIE[md5($_SERVER[\"H\\x54T\\x50_H\\x4f\\x53T\"]).\"\\x61j" ascii
      $s19 = "ram(\"HDD\\x20spa\\x63e\",ex(\"d\\x66 -\\x68\"));showSecParam(\"\\x48o\\x73\\x74s\",@file_get_contents(\"/et\\x63/ho\\x73\\x74s" ascii
      $s20 = "42\\x41\\x4cS\"}[\"\\x77\\x6a\\x6f\\x61q\\x75\\x6f\\x6d\\x63\"]}=curl_init(\"fil\\x65://\".$_POST[\"\\x702\"].\"\\x00\".SELF_PAT" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule Predator_encodedc0032247_4e07_4c7b_8adc_9d5261f5c792 {
   meta:
      description = "php - file Predator-encodedc0032247-4e07-4c7b-8adc-9d5261f5c792.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"
   strings:
      $x1 = " goto XrOFg; FW9lO: function GD6A_() { goto yjTE8; VvSif: frtDo: goto mvvut; EAZou: $_SESSION[\"\\145\\x64\\x69\\164\"] = 0; got" ascii
      $s2 = "    |     Predator Shell  - leetc0des.blogspot.com     |" fullword ascii
      $s3 = "HI9 = ftp_login($bl3F2, $zII0b, $I1__T); goto xD6l7; wHH_s: goto nqNEp; goto ugLCZ; JmuS5: ftp_quit($bl3F2); goto kpo2Z; TYuqo: " ascii
      $s4 = "d($rVRLA, 1024); goto z598A; rvnnb: $wmjSa = shell_exec($frdKa); goto IrZqr; YCIyX: goto Up4SR; goto gj5DD; HPG14: exec($frdKa, " ascii
      $s5 = "1 != strlen($v1njx) - 1) { goto xKXti; } goto iXWpv; mLQrX: chdir($_SESSION[\"\\x70\\167\\144\"]); goto kdHRr; ODUQA: WE6lz: got" ascii
      $s6 = " goto xTEyW; } goto sR35F; TxTKM: error_reporting(0); goto cBl1c; pLzda: echo nPL0n(diskfreespace(getcwd())); goto wsuNN; wzf3t:" ascii
      $s7 = "ob_get_contents(); goto kMrW3; IrZqr: goto Up4SR; goto jnLT2; NraCh: goto Up4SR; goto U6lUU; U6lUU: NI4GT: goto rvnnb; gj5DD: I3" ascii
      $s8 = "o D0woW; vaATA: function SBWNF($frdKa) { goto UR27q; kMrW3: ob_end_clean(); goto NraCh; D0Cbo: $wmjSa = ob_get_contents(); goto " ascii
      $s9 = " { goto L4oTb; } goto n02aL; DmBTg: function vr1k8($frdKa) { goto DkK0B; FcljY: file_get_contents($frdKa); goto AOuH4; wWJHi: in" ascii
      $s10 = "\\116\\x3c\\x2f\\146\\x6f\\x6e\\x74\\76\"; goto reQ77; LoSHZ: } goto xM25I; VpJwJ: echo \"\\56\\x2e\\56\" . substr($GpeM1, strle" ascii
      $s11 = "ipslashes($_POST[\"\\154\\x6f\\x67\\x66\"])); goto GCLQX; diRA3: fputs(fopen($_SESSION[\"\\146\\x69\\x6c\\145\\156\\141\\155\\x6" ascii
      $s12 = "POST[\"\\164\\171\\160\\x65\"] == 2) { goto KQ3yG; } goto ihY4d; rVYVz: goto m8tfd; goto U2fmQ; xTW2n: if ($_SESSION[\"\\163\\x6" ascii
      $s13 = "; } goto Ez8Lz; h4usn: Wryxu: goto sfxYO; jVll6: xKXti: goto j7HJx; Ez8Lz: $_SESSION[\"\\160\\167\\x64\"] = stripslashes($_POST[" ascii
      $s14 = "oto NKBRC; NKBRC: $wmjSa = get_current_user(); goto siVfG; IOvCk: L_S4c: goto E1AhJ; F6ECr: return $wmjSa; goto obYG2; siVfG: if" ascii
      $s15 = "oto Qd5tT; teTB1: goto Zpe4x; goto k07K2; FHBkV: echo htmlspecialchars(fread(fopen(stripslashes($_POST[\"\\x76\\x61\\x6c\\x75\\1" ascii
      $s16 = "1njx) - 1) { goto XC1Vf; } goto JWxEL; hyKqf: if ($GpeM1 = strrpos($v1njx, \"\\134\")) { goto Wryxu; } goto XLk4k; sfxYO: if ($G" ascii
      $s17 = "L_S4c; } goto TonFs; E1AhJ: owZ34: goto F6ECr; TonFs: $wmjSa = \"\\165\\151\\x64\\75\" . getmyuid() . \"\\x28\" . get_current_us" ascii
      $s18 = " goto w8xNf; HJ6wO: $_SESSION[\"\\146\\151\\154\\x65\\156\\141\\x6d\\x65\"] = $_POST[\"\\166\\141\\154\\165\\145\"]; goto R8vQN;" ascii
      $s19 = "\\x5f\\155\\x6f\\x64\\145\"] == 1) { goto BJtrf; } goto d5eo1; VESjd: P7poz: goto vPr4M; jmyRZ: if ($_POST[\"\\164\\171\\160\\14" ascii
      $s20 = "\\160\\145\"] == 14) { goto JrpnT; } goto Ti4X1; LPNyj: MNO0t: goto fvtuQ; d1djV: echo htmlspecialchars(vR1k8(stripslashes($_POS" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule wso2_77af2ddf3_98e1_45d5_b018_61528d1b916e {
   meta:
      description = "php - file wso2.77af2ddf3-98e1-45d5-b018-61528d1b916e.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "ed45d742830cbd157ab612c564b5c6e567971ab441e992da73ef3aac9b8bab24"
   strings:
      $s1 = "SUlJSUlJMTFsMT0nZnRwX2xvZ2luJzskSUlJSUlJSUkxMWxsPSdmdHBfY2xvc2UnOyRJSUlJSUlJSTExbEk9J2lzX2FycmF5JzskSUlJSUlJSUkxMUkxPSdmaWxlJzsk" ascii /* base64 encoded string 'IIIIII11l1='ftp_login';$IIIIIIII11ll='ftp_close';$IIIIIIII11lI='is_array';$IIIIIIII11I1='file';$' */
      $s2 = "b25fZGVzdHJveSc7JElJSUlJSUlsSWxJST0ndW5saW5rJzskSUlJSUlJSWxJSTExPSdiYXNlNjRfZGVjb2RlJzskSUlJSUlJSUkxMTFJPSdmdHBfY29ubmVjdCc7JElJ" ascii /* base64 encoded string 'on_destroy';$IIIIIIIlIlII='unlink';$IIIIIIIlII11='base64_decode';$IIIIIIII111I='ftp_connect';$II' */
      $s3 = "JElJSUlJSUlJMUlsbD0nY2VpbCc7JElJSUlJSUlJMUlJbD0nb2Jfc3RhcnQnOyRJSUlJSUlJSWwxMTE9J3Jlc2V0JzskSUlJSUlJSUlsMTFsPSdmb3Blbic7JElJSUlJ" ascii /* base64 encoded string '$IIIIIIII1Ill='ceil';$IIIIIIII1IIl='ob_start';$IIIIIIIIl111='reset';$IIIIIIIIl11l='fopen';$IIIII' */
      $s4 = "SUlJbDFsMT0naXNfbnVtZXJpYyc7JElJSUlJSUlJbGwxMT0nZndyaXRlJzskSUlJSUlJSUlsbGxJPSdpbXBsb2RlJzskSUlJSUlJSUlsbEkxPSdhZGRzbGFzaGVzJzsk" ascii /* base64 encoded string 'IIIl1l1='is_numeric';$IIIIIIIIll11='fwrite';$IIIIIIIIlllI='implode';$IIIIIIIIllI1='addslashes';$' */
      $s5 = "OyRJSUlJSUlJMUlJMTE9J3JlbmFtZSc7JElJSUlJSUkxSUkxbD0nYXJyYXlfbWFwJzskSUlJSUlJSTFJSWwxPSdyZWFscGF0aCc7JElJSUlJSUkxSUlsST0nZXNjYXBl" ascii /* base64 encoded string ';$IIIIIII1II11='rename';$IIIIIII1II1l='array_map';$IIIIIII1IIl1='realpath';$IIIIIII1IIlI='escape' */
      $s6 = "SUlJSUlJSTFJMWxJPSdmaWxlbXRpbWUnOyRJSUlJSUlJMUkxSUk9J2lzX2xpbmsnOyRJSUlJSUlJMUlsMTE9J2ZpbGVvd25lcic7JElJSUlJSUkxSWxsMT0ncmVhZGxp" ascii /* base64 encoded string 'IIIIIII1I1lI='filemtime';$IIIIIII1I1II='is_link';$IIIIIII1Il11='fileowner';$IIIIIII1Ill1='readli' */
      $s7 = "PSdhcnJheV91bmlxdWUnOyRJSUlJSUlsSWwxMWw9J3N0cnRvdXBwZXInOyRJSUlJSUlsSWwxbDE9J2luX2FycmF5JzskSUlJSUlJbElsMWxJPSdkZWNoZXgnOyRJSUlJ" ascii /* base64 encoded string '='array_unique';$IIIIIIlIl11l='strtoupper';$IIIIIIlIl1l1='in_array';$IIIIIIlIl1lI='dechex';$IIII' */
      $s8 = "JElJSUlJSWxJbGxsST0nZmx1c2gnOyRJSUlJSUlsSWxsSWw9J3JhbmQnOyRJSUlJSUlsSWxJbGw9J3JvdW5kJzskSUlJSUlJbElsSUlJPSdmc29ja29wZW4nOyRJSUlJ" ascii /* base64 encoded string '$IIIIIIlIlllI='flush';$IIIIIIlIllIl='rand';$IIIIIIlIlIll='round';$IIIIIIlIlIII='fsockopen';$IIII' */
      $s9 = "bGVncm91cCc7JElJSUlJSUlsMUkxMT0ncHJlZ19tYXRjaCc7JElJSUlJSUlsMUlJMT0nZmVvZic7JElJSUlJSUlsMUlJbD0nZXhlYyc7JElJSUlJSUlsMUlJST0ncGNs" ascii /* base64 encoded string 'legroup';$IIIIIIIl1I11='preg_match';$IIIIIIIl1II1='feof';$IIIIIIIl1IIl='exec';$IIIIIIIl1III='pcl' */
      $s10 = "bGUnOyRJSUlJSUlsSUlsSUk9J2ZpbGVhdGltZSc7JElJSUlJSWxJSUkxMT0nZmlsZWN0aW1lJzskSUlJSUlJbElJSWwxPSdpbmlfcmVzdG9yZSc7JElJSUlJSWxJSUls" ascii /* base64 encoded string 'le';$IIIIIIlIIlII='fileatime';$IIIIIIlIII11='filectime';$IIIIIIlIIIl1='ini_restore';$IIIIIIlIIIl' */
      $s11 = "bGltaXQnOyRJSUlJSUlJMWxsSUk9J2FkZGNzbGFzaGVzJzskSUlJSUlJSTFsSTExPSdpY29udic7JElJSUlJSUkxbElsMT0naXNfd3JpdGFibGUnOyRJSUlJSUlJMWxJ" ascii /* base64 encoded string 'limit';$IIIIIII1llII='addcslashes';$IIIIIII1lI11='iconv';$IIIIIII1lIl1='is_writable';$IIIIIII1lI' */
      $s12 = "c2hlbGxhcmcnOyRJSUlJSUlJMUlJSWw9J2lzX2ZpbGUnOyRJSUlJSUlJMUlJSUk9J2NvcHknOyRJSUlJSUlJbDExbGw9J2NoZGlyJzskSUlJSUlJSWwxMWxJPSdiYXNl" ascii /* base64 encoded string 'shellarg';$IIIIIII1IIIl='is_file';$IIIIIII1IIII='copy';$IIIIIIIl11ll='chdir';$IIIIIIIl11lI='base' */
      $s13 = "bmFtZSc7JElJSUlJSUlsMTFJMT0ncm1kaXInOyRJSUlJSUlJbDExSWw9J2Nsb3NlZGlyJzskSUlJSUlJSWwxMUlJPSdvcGVuZGlyJzskSUlJSUlJSWwxbDExPSdmaWxl" ascii /* base64 encoded string 'name';$IIIIIIIl11I1='rmdir';$IIIIIIIl11Il='closedir';$IIIIIIIl11II='opendir';$IIIIIIIl1l11='file' */
      $s14 = "SUlsSUkxMWw9J3N0cmlwc2xhc2hlcyc7JElJSUlJSWxJSTFJMT0nc3RydG90aW1lJzskSUlJSUlJbElJMUlsPSdvcmQnOyRJSUlJSUlsSUlsMTE9J3RvdWNoJzskSUlJ" ascii /* base64 encoded string 'IIlII11l='stripslashes';$IIIIIIlII1I1='strtotime';$IIIIIIlII1Il='ord';$IIIIIIlIIl11='touch';$III' */
      $s15 = "bGw9J2ZpbGVwZXJtcyc7JElJSUlJSUkxSTExMT0ncHJlZ19yZXBsYWNlJzskSUlJSUlJSTFJMWwxPSd1cmxlbmNvZGUnOyRJSUlJSUlJMUkxbGw9J2ZpbGVzaXplJzsk" ascii /* base64 encoded string 'll='fileperms';$IIIIIII1I111='preg_replace';$IIIIIII1I1l1='urlencode';$IIIIIII1I1ll='filesize';$' */
      $s16 = "SUlJbElJbDFJPSdwb3cnOyRJSUlJSUlsSUlsbDE9J2NsZWFyc3RhdGNhY2hlJzskSUlJSUlJbElJbGxJPSdjaG1vZCc7JElJSUlJSWxJSWxJMT0naGlnaGxpZ2h0X2Zp" ascii /* base64 encoded string 'IIIlIIl1I='pow';$IIIIIIlIIll1='clearstatcache';$IIIIIIlIIllI='chmod';$IIIIIIlIIlI1='highlight_fi' */
      $s17 = "eXN0ZW0nOyRJSUlJSUlJbGwxbGw9J3BvcGVuJzskSUlJSUlJSWxsMWxJPSdpc19yZXNvdXJjZSc7JElJSUlJSUlsbDFJMT0nZnJlYWQnOyRJSUlJSUlJbGwxSWw9J3No" ascii /* base64 encoded string 'ystem';$IIIIIIIll1ll='popen';$IIIIIIIll1lI='is_resource';$IIIIIIIll1I1='fread';$IIIIIIIll1Il='sh' */
      $s18 = "SUlJSUlJbEkxbEk9J3N0cnRvbG93ZXInOyRJSUlJSUlJbElsMTE9J2lzX3JlYWRhYmxlJzskSUlJSUlJSWxJbDFJPSdzdHJwb3MnOyRJSUlJSUlJbElsSTE9J3Nlc3Np" ascii /* base64 encoded string 'IIIIIIlI1lI='strtolower';$IIIIIIIlIl11='is_readable';$IIIIIIIlIl1I='strpos';$IIIIIIIlIlI1='sessi' */
      $s19 = "bD0nZ2xvYic7JElJSUlJSWxJSUlJMT0ndGVtcG5hbSc7JElJSUlJSUkxMUlJbD0ncmFuZ2UnOyRJSUlJSUlJMWwxMWw9J2dldG15Z2lkJzskSUlJSUlJSTFsMTFJPSdn" ascii /* base64 encoded string 'l='glob';$IIIIIIlIIII1='tempnam';$IIIIIII11IIl='range';$IIIIIII1l11l='getmygid';$IIIIIII1l11I='g' */
      $s20 = "b3NlJzskSUlJSUlJSWxsMTExPSdwYXNzdGhydSc7JElJSUlJSUlsbDExbD0nb2JfZ2V0X2NsZWFuJzskSUlJSUlJSWxsMTFJPSdqb2luJzskSUlJSUlJSWxsMWwxPSdz" ascii /* base64 encoded string 'ose';$IIIIIIIll111='passthru';$IIIIIIIll11l='ob_get_clean';$IIIIIIIll11I='join';$IIIIIIIll1l1='s' */
   condition:
      uint16(0) == 0x3f3c and filesize < 1000KB and
      8 of them
}

rule wso2_8cb0c936b_b009_41a7_b503_5e323d207445 {
   meta:
      description = "php - file wso2.8cb0c936b-b009-41a7-b503-5e323d207445.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "fd953c4f799a538beb99962b0249f7a3a2dfc81345d7f47fa8842e3e76197b0e"
   strings:
      $s1 = "SUlJSUlJMTFsMT0nZnRwX2xvZ2luJzskSUlJSUlJSUkxMWxsPSdmdHBfY2xvc2UnOyRJSUlJSUlJSTExbEk9J2lzX2FycmF5JzskSUlJSUlJSUkxMUkxPSdmaWxlJzsk" ascii /* base64 encoded string 'IIIIII11l1='ftp_login';$IIIIIIII11ll='ftp_close';$IIIIIIII11lI='is_array';$IIIIIIII11I1='file';$' */
      $s2 = "b25fZGVzdHJveSc7JElJSUlJSUlsSWxJST0ndW5saW5rJzskSUlJSUlJSWxJSTExPSdiYXNlNjRfZGVjb2RlJzskSUlJSUlJSUkxMTFJPSdmdHBfY29ubmVjdCc7JElJ" ascii /* base64 encoded string 'on_destroy';$IIIIIIIlIlII='unlink';$IIIIIIIlII11='base64_decode';$IIIIIIII111I='ftp_connect';$II' */
      $s3 = "JElJSUlJSUlJMUlsbD0nY2VpbCc7JElJSUlJSUlJMUlJbD0nb2Jfc3RhcnQnOyRJSUlJSUlJSWwxMTE9J3Jlc2V0JzskSUlJSUlJSUlsMTFsPSdmb3Blbic7JElJSUlJ" ascii /* base64 encoded string '$IIIIIIII1Ill='ceil';$IIIIIIII1IIl='ob_start';$IIIIIIIIl111='reset';$IIIIIIIIl11l='fopen';$IIIII' */
      $s4 = "SUlJbDFsMT0naXNfbnVtZXJpYyc7JElJSUlJSUlJbGwxMT0nZndyaXRlJzskSUlJSUlJSUlsbGxJPSdpbXBsb2RlJzskSUlJSUlJSUlsbEkxPSdhZGRzbGFzaGVzJzsk" ascii /* base64 encoded string 'IIIl1l1='is_numeric';$IIIIIIIIll11='fwrite';$IIIIIIIIlllI='implode';$IIIIIIIIllI1='addslashes';$' */
      $s5 = "OyRJSUlJSUlJMUlJMTE9J3JlbmFtZSc7JElJSUlJSUkxSUkxbD0nYXJyYXlfbWFwJzskSUlJSUlJSTFJSWwxPSdyZWFscGF0aCc7JElJSUlJSUkxSUlsST0nZXNjYXBl" ascii /* base64 encoded string ';$IIIIIII1II11='rename';$IIIIIII1II1l='array_map';$IIIIIII1IIl1='realpath';$IIIIIII1IIlI='escape' */
      $s6 = "SUlJSUlJSTFJMWxJPSdmaWxlbXRpbWUnOyRJSUlJSUlJMUkxSUk9J2lzX2xpbmsnOyRJSUlJSUlJMUlsMTE9J2ZpbGVvd25lcic7JElJSUlJSUkxSWxsMT0ncmVhZGxp" ascii /* base64 encoded string 'IIIIIII1I1lI='filemtime';$IIIIIII1I1II='is_link';$IIIIIII1Il11='fileowner';$IIIIIII1Ill1='readli' */
      $s7 = "PSdhcnJheV91bmlxdWUnOyRJSUlJSUlsSWwxMWw9J3N0cnRvdXBwZXInOyRJSUlJSUlsSWwxbDE9J2luX2FycmF5JzskSUlJSUlJbElsMWxJPSdkZWNoZXgnOyRJSUlJ" ascii /* base64 encoded string '='array_unique';$IIIIIIlIl11l='strtoupper';$IIIIIIlIl1l1='in_array';$IIIIIIlIl1lI='dechex';$IIII' */
      $s8 = "JElJSUlJSWxJbGxsST0nZmx1c2gnOyRJSUlJSUlsSWxsSWw9J3JhbmQnOyRJSUlJSUlsSWxJbGw9J3JvdW5kJzskSUlJSUlJbElsSUlJPSdmc29ja29wZW4nOyRJSUlJ" ascii /* base64 encoded string '$IIIIIIlIlllI='flush';$IIIIIIlIllIl='rand';$IIIIIIlIlIll='round';$IIIIIIlIlIII='fsockopen';$IIII' */
      $s9 = "bGVncm91cCc7JElJSUlJSUlsMUkxMT0ncHJlZ19tYXRjaCc7JElJSUlJSUlsMUlJMT0nZmVvZic7JElJSUlJSUlsMUlJbD0nZXhlYyc7JElJSUlJSUlsMUlJST0ncGNs" ascii /* base64 encoded string 'legroup';$IIIIIIIl1I11='preg_match';$IIIIIIIl1II1='feof';$IIIIIIIl1IIl='exec';$IIIIIIIl1III='pcl' */
      $s10 = "bGUnOyRJSUlJSUlsSUlsSUk9J2ZpbGVhdGltZSc7JElJSUlJSWxJSUkxMT0nZmlsZWN0aW1lJzskSUlJSUlJbElJSWwxPSdpbmlfcmVzdG9yZSc7JElJSUlJSWxJSUls" ascii /* base64 encoded string 'le';$IIIIIIlIIlII='fileatime';$IIIIIIlIII11='filectime';$IIIIIIlIIIl1='ini_restore';$IIIIIIlIIIl' */
      $s11 = "bGltaXQnOyRJSUlJSUlJMWxsSUk9J2FkZGNzbGFzaGVzJzskSUlJSUlJSTFsSTExPSdpY29udic7JElJSUlJSUkxbElsMT0naXNfd3JpdGFibGUnOyRJSUlJSUlJMWxJ" ascii /* base64 encoded string 'limit';$IIIIIII1llII='addcslashes';$IIIIIII1lI11='iconv';$IIIIIII1lIl1='is_writable';$IIIIIII1lI' */
      $s12 = "c2hlbGxhcmcnOyRJSUlJSUlJMUlJSWw9J2lzX2ZpbGUnOyRJSUlJSUlJMUlJSUk9J2NvcHknOyRJSUlJSUlJbDExbGw9J2NoZGlyJzskSUlJSUlJSWwxMWxJPSdiYXNl" ascii /* base64 encoded string 'shellarg';$IIIIIII1IIIl='is_file';$IIIIIII1IIII='copy';$IIIIIIIl11ll='chdir';$IIIIIIIl11lI='base' */
      $s13 = "bmFtZSc7JElJSUlJSUlsMTFJMT0ncm1kaXInOyRJSUlJSUlJbDExSWw9J2Nsb3NlZGlyJzskSUlJSUlJSWwxMUlJPSdvcGVuZGlyJzskSUlJSUlJSWwxbDExPSdmaWxl" ascii /* base64 encoded string 'name';$IIIIIIIl11I1='rmdir';$IIIIIIIl11Il='closedir';$IIIIIIIl11II='opendir';$IIIIIIIl1l11='file' */
      $s14 = "SUlsSUkxMWw9J3N0cmlwc2xhc2hlcyc7JElJSUlJSWxJSTFJMT0nc3RydG90aW1lJzskSUlJSUlJbElJMUlsPSdvcmQnOyRJSUlJSUlsSUlsMTE9J3RvdWNoJzskSUlJ" ascii /* base64 encoded string 'IIlII11l='stripslashes';$IIIIIIlII1I1='strtotime';$IIIIIIlII1Il='ord';$IIIIIIlIIl11='touch';$III' */
      $s15 = "bGw9J2ZpbGVwZXJtcyc7JElJSUlJSUkxSTExMT0ncHJlZ19yZXBsYWNlJzskSUlJSUlJSTFJMWwxPSd1cmxlbmNvZGUnOyRJSUlJSUlJMUkxbGw9J2ZpbGVzaXplJzsk" ascii /* base64 encoded string 'll='fileperms';$IIIIIII1I111='preg_replace';$IIIIIII1I1l1='urlencode';$IIIIIII1I1ll='filesize';$' */
      $s16 = "SUlJbElJbDFJPSdwb3cnOyRJSUlJSUlsSUlsbDE9J2NsZWFyc3RhdGNhY2hlJzskSUlJSUlJbElJbGxJPSdjaG1vZCc7JElJSUlJSWxJSWxJMT0naGlnaGxpZ2h0X2Zp" ascii /* base64 encoded string 'IIIlIIl1I='pow';$IIIIIIlIIll1='clearstatcache';$IIIIIIlIIllI='chmod';$IIIIIIlIIlI1='highlight_fi' */
      $s17 = "eXN0ZW0nOyRJSUlJSUlJbGwxbGw9J3BvcGVuJzskSUlJSUlJSWxsMWxJPSdpc19yZXNvdXJjZSc7JElJSUlJSUlsbDFJMT0nZnJlYWQnOyRJSUlJSUlJbGwxSWw9J3No" ascii /* base64 encoded string 'ystem';$IIIIIIIll1ll='popen';$IIIIIIIll1lI='is_resource';$IIIIIIIll1I1='fread';$IIIIIIIll1Il='sh' */
      $s18 = "SUlJSUlJbEkxbEk9J3N0cnRvbG93ZXInOyRJSUlJSUlJbElsMTE9J2lzX3JlYWRhYmxlJzskSUlJSUlJSWxJbDFJPSdzdHJwb3MnOyRJSUlJSUlJbElsSTE9J3Nlc3Np" ascii /* base64 encoded string 'IIIIIIlI1lI='strtolower';$IIIIIIIlIl11='is_readable';$IIIIIIIlIl1I='strpos';$IIIIIIIlIlI1='sessi' */
      $s19 = "bD0nZ2xvYic7JElJSUlJSWxJSUlJMT0ndGVtcG5hbSc7JElJSUlJSUkxMUlJbD0ncmFuZ2UnOyRJSUlJSUlJMWwxMWw9J2dldG15Z2lkJzskSUlJSUlJSTFsMTFJPSdn" ascii /* base64 encoded string 'l='glob';$IIIIIIlIIII1='tempnam';$IIIIIII11IIl='range';$IIIIIII1l11l='getmygid';$IIIIIII1l11I='g' */
      $s20 = "b3NlJzskSUlJSUlJSWxsMTExPSdwYXNzdGhydSc7JElJSUlJSUlsbDExbD0nb2JfZ2V0X2NsZWFuJzskSUlJSUlJSWxsMTFJPSdqb2luJzskSUlJSUlJSWxsMWwxPSdz" ascii /* base64 encoded string 'ose';$IIIIIIIll111='passthru';$IIIIIIIll11l='ob_get_clean';$IIIIIIIll11I='join';$IIIIIIIll1l1='s' */
   condition:
      uint16(0) == 0x3f3c and filesize < 1000KB and
      8 of them
}

rule pHpINJ_encoded3d211e70_26af_4985_9166_e84bdf6444fc {
   meta:
      description = "php - file pHpINJ-encoded3d211e70-26af-4985-9166-e84bdf6444fc.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "50389c3b95a9de00220fc554258fda1fef01c62dad849e66c8a92fc749523457"
   strings:
      $s1 = "    |     News PHP Shell  - leetc0des.blogspot.com     |" fullword ascii
      $s2 = " goto rIXTF; OWS97: echo \"\\x41\\146\\x74\\145\\x72\\40\\143\\154\\x69\\x63\\153\\151\\156\\x67\\40\\147\\157\\40\\x74\\157\\x2" ascii
      $s3 = "\\141\\76\\x20\\x3c\\x62\\162\\x20\\x2f\\76\"; goto OWS97; jJdxY: $XXnBi = $_POST[\"\\165\\162\\x6c\"]; goto Tee4Q; lZk1j: $bPSw" ascii
      $s4 = "W00TE; Tee4Q: $IHNPn = $_POST[\"\\160\\x61\\164\\x68\\62\\156\\x65\\x77\\x73\"]; goto lZk1j; rIXTF: $MjJzP = \"\\112\\x48\\132" ascii
      $s5 = "rlencode($lIMk3); goto n0Oy7; W00TE: if (isset($_POST[\"\\165\\162\\x6c\"])) { goto LPemK; } goto WKGbS; n0Oy7: $tg7so = $XXnBi " ascii
      $s6 = "eval(base64_decode($MjJzP)); goto OYM8Z; AGwTP: $lIMk3 = \"\\60\\x27\\x20\\x55\\116\\111\\117\\x4e\\40\\x53\\105\\114\\x45\\x43" ascii
      $s7 = "\\x64\\107\\x4d\\160\\117\\167\\75\\x3d\"; goto Mu_K9; O42Gv: bc6am: goto isn6y; MVE1C: LPemK: goto jJdxY; uksu8: echo \"\\x3c" ascii
      $s8 = "7\\151\\144\\75\" . $lIMk3; goto uksu8; WKGbS: echo \"\\125\\162\\154\\40\\x74\\x6f\\x20\\x69\\x6e\\144\\x65\\170\\56\\x70\\x68" ascii
      $s9 = "3f\\x3e\\x27\\x20\\54\\x30\\x20\\54\\60\\x20\\54\\60\\40\\54\\x30\\40\\111\\x4e\\x54\\117\\x20\\117\\125\\x54\\106\\x49\\114\\x4" ascii
      $s10 = "7\\165\\164\\x66\\x69\\x6c\\145\"]; goto AGwTP; WY6eB: goto bc6am; goto MVE1C; ei3w1: echo \"\\42\\40\\155\\x65\\164\\x68\\x6f" ascii
      $s11 = "x78\\x70\\154\\157\\x69\\x74\\42\\x3e\\x20\\74\\x62\\162\\x20\\57\\x3e\\x20\\x3c\\x62\\x72\\x20\\x2f\\x3e\\xa\\12\\12\\12\"; got" ascii
      $s12 = "f\\x53\\x45\\114\\106\"]}\"; goto ei3w1; isn6y: echo \"\\x3c\\57\\x62\\x6f\\x64\\x79\\x3e\\12\\74\\x2f\\x68\\x74\\x6d\\x6c\\x3e" ascii
      $s13 = " goto rIXTF; OWS97: echo \"\\x41\\146\\x74\\145\\x72\\40\\143\\154\\x69\\x63\\153\\151\\156\\x67\\40\\147\\157\\40\\x74\\157\\x2" ascii
      $s14 = "0; OYM8Z: echo \"\\74\\150\\x74\\155\\154\\x3e\\xa\\x3c\\x68\\145\\x61\\x64\\x3e\\12\\x3c\\x74\\x69\\x74\\x6c\\x65\\x3e\\x7c\\x7" ascii
      $s15 = "2\\x20\\57\\76\\xa\\74\\x66\\157\\x72\\155\\40\\141\\x63\\164\\151\\157\\x6e\\40\\75\\x20\\x22\"; goto BI7iq; BI7iq: echo \"{$_S" ascii
      $s16 = "4\\x6c\\56\\160\\150\\x70\\77\\143\\x70\\143\\x3d\\x6c\\x73\\x20\\x74\\x6f\\x20\\x73\\145\\145\\40\\x72\\145\\x73\\165\\x6c\\x74" ascii
      $s17 = "\\x49\\151\\130\\124\\x73\\x4e\\103\\151\\x41\\147\\x4a\\110\\144\\x6c\\131\\x69\\101\\147\\111\\x43\\x41\\x67\\x50\\123\\101\\1" ascii
      $s18 = "\\143\\104\\x6f\\166\\x4c\\171\\122\\x30\\x59\\x58\\x4a\\x6e\\132\\x58\\x51\\x67\\131\\x6e\\153\\147\\112\\x48\\132\\160\\x63\\x" ascii
      $s19 = "\\156\\72\\72\\56\\40\\40\\x20\\x7c\\x7c\\74\\57\\150\\145\\141\\144\\x65\\x72\\x3e\\40\\x3c\\142\\x72\\x20\\57\\x3e\\x20\\x3c" ascii
      $s20 = "\\63\\x64\\x58\\x4a\\163\\132\\x47\\126\\x6a\\142\\62\\122\\x6c\\113\\103\\122\\x33\\x5a\\x57\\x49\\165\\112\\107\\x6c\\x75\\141" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 20KB and
      8 of them
}

rule phpsploit9343ec33_0753_4b9d_9539_c95aabc42f04 {
   meta:
      description = "php - file phpsploit9343ec33-0753-4b9d-9539-c95aabc42f04.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "bdb0eceb6b8398f23132951068a14d51f556623ce8c42e7c453c976abea72884"
   strings:
      $s1 = "interactive shell-like connection over HTTP between client and web server." fullword ascii
      $s2 = "https://github.com/nil0x42/phpsploit" fullword ascii
      $s3 = "def run_process(cmd):" fullword ascii
      $s4 = "        if cmdrun(iface, \"set TARGET '%s'\" % opt['target']) != 0:" fullword ascii
      $s5 = "    p.description = \"The stealth post-exploitation framework\"" fullword ascii
      $s6 = "    if cmdrun(iface, \"source -e '%s'\" % opt['config'], show_err=True) != 0:" fullword ascii
      $s7 = "\"\"\"PhpSploit: Furtive post-exploitation framework" fullword ascii
      $s8 = "# check operating system" fullword ascii
      $s9 = "    \"\"\"get output of given shell command\"\"\"" fullword ascii
      $s10 = "            parser.error(\"%r: couldn't set target url.\" % opt['target'])" fullword ascii
      $s11 = "    \"\"\"run a phpsploit command" fullword ascii
      $s12 = "                   help=\"run phpsploit command (disables interactive mode)\"," fullword ascii
      $s13 = "             \"`pip3 install -r requirements.txt`\")" fullword ascii
      $s14 = "        parser.error(\"%r: config file contains invalid commands.\"" fullword ascii
      $s15 = "                   help=\"set remote TARGET URL\"," fullword ascii
      $s16 = "        print(\"PhpSploit Framework, version %s\\n\"" fullword ascii
      $s17 = "    import subprocess as sp" fullword ascii
      $s18 = "It is a post-exploitation tool capable to maintain access to a compromised" fullword ascii
      $s19 = "PhpSploit is a remote control framework, aiming to provide a stealth" fullword ascii
      $s20 = "# check python version" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 20KB and
      8 of them
}

rule Alfa_Shell_Privc16f1860_cbf7_454e_bf6c_c1e2f65a85f3 {
   meta:
      description = "php - file Alfa Shell Privc16f1860-cbf7-454e-bf6c-c1e2f65a85f3.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "2533119903008643c2a6bbce432eb9af1e70457764762d2668f03ed58dd886ee"
   strings:
      $x1 = "<?php ${\"\\x47\\x4c\\x4fBAL\\x53\"}[\"l\\x6c\\x6b\\x71q\\x78\\x70v\\x66j\\x63\"]=\"c\\x72\";${\"\\x47LO\\x42\\x41\\x4cS\"}[\"rw" ascii
      $s2 = "\"\\x3cb\\x72 /\\x3eU\\x73\\x65r I\\x50:\\x20\".$_SERVER[\"\\x52\\x45M\\x4fTE_\\x41DD\\x52\"].(isset($_SERVER[\"HTTP_\\x58\\x5fF" ascii
      $s3 = "\\x73_list\"=>\"\\x230\\x30FF\\x30\\x30\",\"\\x6f\\x70\\x74ions\\x5flist:\\x68o\\x76e\\x72\"=>\"\\x23F\\x46\\x46FF\\x46\",\"\\x6" ascii
      $s4 = "\\x64pu\"]}=\"\";}while(${$bmeyemldfv}<strlen(${${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x71sa\\x64\\x64\\x6a\\x67\\x62g" ascii
      $s5 = "23FFF\\x46F\\x46\",\"\\x75\\x70\\x6coad\\x65r_t\\x65\\x78t\\x5fl\\x65ft\"=>\"\\x232\\x35\\x66\\x66\\x30\\x30\",\"\\x75p\\x6c\\x6" ascii
      $s6 = "FEE\",\"s\\x65\\x6c\\x65\\x63t\\x5f\\x62\\x6fx:\\x68\\x6fver\"=>\"#\\x32\\x37\\x397\\x39B\",\"\\x62\\x75tton_\\x62\\x6f\\x72de" ascii
      $s7 = "\\x79r\\x6cj\\x6a\"]}).charAt(${${\"\\x47\\x4cO\\x42\\x41L\\x53\"}[\"\\x71\\x79j\\x72t\\x6asf\\x67\\x7a\\x76\"]},${${\"\\x47L\\x" ascii
      $s8 = "\\x56\\x70\\x35\\x6d\\x75\\x4elIcT+dX\\x46\\x32\\x32\\x32Ud3\\x481\\x30\\x413lOGuy\\x42\\x6e3wlU\\x75rk\\x30s/6\\x4fJ\\x61\\x46m" ascii
      $s9 = "x22j\\x61va\\x73\\x63ri\\x70\\x74\\\"\\x3e\\n<!--\\n\\x64\\x6fc\\x75\\x6d\\x65nt\\x2e\\x77ri\\x74\\x65(\\x4f\\x54);\\n// --></s" ascii
      $s10 = "\\x4ce\\x52pmPOz\\x73\\x4e\\x36EVj3g+\\x6d\\x31\\x53l\\x4e\\x65\\x33\\x43Z9\\x6b\\x66\\x49P\\x48\\x592S\\x35\\x30M3IrcBvTtO+\\x4" ascii
      $s11 = "\\x75\\x6e\\x65\\x55\\x44O\\x76at\\x4e+\\x43c4\\x6cDF\\x48\\x4e+B\\x74\\x32GkKMI\\x78\\x6eQ\\x33F\\x46/G\\x52\\x4cm+K\\x4b+l\\x7" ascii
      $s12 = "484\\x6a2f\\x62\\x57\\x71k\\x48lW\\x68\\x65K0\\x71\\x6fV0\\x36\\x79\\x4eurDw\\x39aH\\x5aE\\x7aY\\x46\\x6aVzT\\x51a\\x39\\x73rm" ascii
      $s13 = "50jk\\x42T\\x69x\\x71\\x68\\x6et\\x44wG/rC\\x61\\x44\\x76f\\x6f\\x48bSh\\x47\\x77b\\x67\\x54\\x62\\x72\\x73\\x72\\x73\\x4cQ8\\x3" ascii
      $s14 = "$ycixjm=\"\\x6fut\\x70\\x75\\x74\";$bmeyemldfv=\"i\";${${\"G\\x4cOB\\x41\\x4cS\"}[\"\\x74\\x71h\\x70\\x6f\\x66\\x61y\\x65\\x71\"" ascii
      $s15 = "30\",\"\\x68\\x65ad\\x65\\x72\\x5f\\x70\\x77d:ho\\x76er\"=>\"\\x23\\x46\\x46\\x46FF\\x46\",\"h\\x65ader\\x5fdrive\"=>\"\\x230\\x" ascii
      $s16 = "x46\\x34R\\x31+\\x56n\\x65qi\\x37\\x72E\\x52q\\x50n66Kn\\x55V0IO\\x4bK33gETRPd\\x49+a\\x37\\x41/O\\x63\\x49njA\\x4b\\x776\\x384Q" ascii
      $s17 = "x67\\x7a\\x76\"]},${${\"G\\x4c\\x4fBALS\"}[\"\\x73vb\\x6dp\\x69z\\x77\\x77\"]}).charAt(${$yhuzcjqqk},${${\"\\x47\\x4cO\\x42A\\x4" ascii
      $s18 = "x47L\\x4f\\x42AL\\x53\"}[\"q\\x79\\x6artj\\x73\\x66g\\x7a\\x76\"]},${$esyelsqtxsr}).charAt(${${\"G\\x4cO\\x42\\x41\\x4cS\"}[\"" ascii
      $s19 = "7I\\x39/\\x6c\\x61\\x62\\x36x\\x42Q\\x377\\x52d\\x6ddj\\x51Mw\\x55bb\\x39\\x4fn\\x34\\x64\\x44m\\x51\\x396Hd4\\x6aDaIIRcZe\\x59H" ascii
      $s20 = "x67\\x49\\x4dqDcraT\\x4e\\x61/L\\x38\\x52j\\x34\\x50\\x659\\x567\\x54oxZm/l\\x4307\\x66+\\x70\\x70k34\\x47za\\x6bU\\x46\\x43\\x5" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule Gazadeab236b_637d_4ecc_8da9_1cdc65097578 {
   meta:
      description = "php - file Gazadeab236b-637d-4ecc-8da9-1cdc65097578.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "9d2ddb1ab1cf3fe22bf7fa2fcb483fae2a7d6c05e4550031ecc78a63bc51ba83"
   strings:
      $x1 = "<?php ${\"GLOBA\\x4cS\"}[\"\\x72\\x67\\x68\\x64\\x72\\x6c\\x76\\x6f\"]=\"ga\\x7a\\x61_\\x74ex\\x74\\x31\";${\"\\x47LOBA\\x4c\\x5" ascii
      $s2 = "2e\\x2e/\".__FILE__);curl_exec(${${\"GL\\x4f\\x42\\x41\\x4cS\"}[\"b\\x6cj\\x6d\\x64\\x6but\\x74\"]});htmlspecialchars(var_dump(c" ascii
      $s3 = "header();echo\"<\\x682\\x20s\\x74\\x79l\\x65=\\\"mar\\x67i\\x6e-b\\x6f\\x74\\x74om:\\x203\\x70\\x74\\\">\".html(${${\"\\x47\\x4c" ascii
      $s4 = "\"ijj\\x63\\x65\\x6b\\x73\"]}).\";\");header(\"\\x43onte\\x6e\\x74-Leng\\x74h:\\x20\".filesize(${${\"\\x47\\x4cOBA\\x4cS\"}[\"" ascii
      $s5 = "\\x67\\x22>\\n\";request_dump();echo\"\\t<b>\".word(\"\\x72\\x65\\x61\\x6c\\x6c\\x79\\x5fdele\\x74e\").\"\\x3c/b>\\n\\t<\\x70>" ascii
      $s6 = "79\\x76\"]=\"\\x73r\\x63\";ob_end_clean();html_header();echo\"\\x3ch\\x32\\x20\\x73t\\x79l\\x65\\x3d\\x22\\x74\\x65\\x78t-\\x61" ascii
      $s7 = "{\"G\\x4c\\x4f\\x42A\\x4c\\x53\"}[\"n\\x67l\\x6f\\x74\\x62\\x63t\\x71\"]}=shell_exec(${${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"" ascii
      $s8 = "fds\"]},\"r\")){$virktyukt=\"\\x73t\\x72\\x65\\x61\\x6d\";$bxxiugjhb=\"\\x73\\x74\\x72\\x65\\x61m\";echo stream_get_contents(${$" ascii
      $s9 = "x20\\x63o\\x6c\\x6fr=\\\"([^\\\"]*)\\\"\\x3e\",\"<\\x73\\x70a\\x6e\\x20\\x73\\x74\\x79\\x6ce\\x3d\\\"c\\x6fl\\x6f\\x72: \\x5c1" ascii
      $s10 = "[\"\\x79dh\\x71\\x63\\x68weomy\"]};}function request_dump(){${\"\\x47LOB\\x41L\\x53\"}[\"o\\x73g\\x6f\\x62\\x64\"]=\"\\x6b\\x65" ascii
      $s11 = "cog\\x22>\\n\\x3ctr\\x3e\\n\\x3ct\\x64\\x20c\\x6c\\x61s\\x73=\\x22dial\\x6fg\\\"\\x3e\\n\";request_dump();${\"\\x47L\\x4f\\x42AL" ascii
      $s12 = ";request_dump();${\"G\\x4c\\x4f\\x42A\\x4c\\x53\"}[\"\\x6bs\\x68\\x74gjid\\x74\\x73k\"]=\"d\\x69\\x72e\\x63tory\";echo\"\\n<b\\x" ascii
      $s13 = "x65\\x72\\x72or:\\x20\".${$msplnikl}.\"\\n\".\"\\x65\\x72\\x72o\\x72\\x20in\\x66o: \".mysql_error().\"\\n\");if(!${${\"G\\x4cOB" ascii
      $s14 = "\\x69re\\x63\\x74o\\x72\\x79\";if(array_key_exists(\"re\\x76\\x65r\\x73e\",$_GET)&&$_GET[\"\\x72ev\\x65\\x72s\\x65\"]==\"\\x74" ascii
      $s15 = "\\x74;\");@mysql_connect($_POST[\"lo\"],$_POST[\"\\x75\\x73\\x65r\"],$_POST[\"p\\x61\\x73\\x73\"])or die(mysql_error());$raxlcun" ascii
      $s16 = "69\"]}<$_POST[\"nu\\x6d\"];${$ddaxfqvuig}++){if(array_key_exists(\"\\x73\\x75\\x62mi\\x74$i\",$_POST))break;}if(${$xtuuqdtg}<$_P" ascii
      $s17 = "4c\\x53\"}[\"\\x62\\x79\\x76pr\\x67k\\x63jv\\x73\"]=\"s\\x6fr\\x74\";$onshntcl=\"r\\x65\\x76\\x65\\x72se\";if(array_key_exists(" ascii
      $s18 = "\"];${${\"G\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x70p\\x6cd\\x6bu\"]}=\"uploa\\x64\";}elseif(array_key_exists(\"nu\\x6d\",$_POST" ascii
      $s19 = "}++){if(array_key_exists(\"\\x63\\x68eck\\x65d$i\",$_POST)&&$_POST[\"\\x63\\x68eck\\x65d$i\"]==\"\\x74\\x72\\x75e\"){${${\"\\x47" ascii
      $s20 = "if(empty(${${\"\\x47\\x4cO\\x42\\x41\\x4c\\x53\"}[\"\\x70\\x70\\x6c\\x64ku\"]})&&(!empty($_POST[\"su\\x62m\\x69t\\x5fcreate\"])|" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule angeleddaaad5_8d12_49ae_a893_b092deeb2eee {
   meta:
      description = "php - file angeleddaaad5-8d12-49ae-a893-b092deeb2eee.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "89c38652727912f590ae5b1ef302de5343d1af1402d6adf2d7dedea3daf9b0f9"
   strings:
      $s1 = "dXQiIG5hbWU9IndyaXRhYmxlZGIiIHZhbHVlPSInLiR3cml0YWJsZWRiLiciIHR5cGU9InRleHQiIC8+PGlucHV0IG5hbWU9ImRpciIgdmFsdWU9IicuJGRpci4nIiB0" ascii /* base64 encoded string 'ut" name="writabledb" value="'.$writabledb.'" type="text" /><input name="dir" value="'.$dir.'" t' */
      $s2 = "ImZpbGUiIC8+PGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0iZGlyIiB2YWx1ZT0iJy4kbm93cGF0aC4nIiAvPjxwPjxpbnB1dCBjbGFzcz0iYnQiIHR5cGU9InN1Ym1p" ascii /* base64 encoded string '"file" /><input type="hidden" name="dir" value="'.$nowpath.'" /><p><input class="bt" type="submi' */
      $s3 = "PjxkaXYgc3R5bGU9ImZsb2F0OnJpZ2h0OyI+PGlucHV0IGNsYXNzPSJpbnB1dCIgbmFtZT0idXBsb2FkZmlsZSIgdmFsdWU9IiIgdHlwZT0iZmlsZSIgLz4gPGlucHV0" ascii /* base64 encoded string '><div style="float:right;"><input class="input" name="uploadfile" value="" type="file" /> <input' */
      $s4 = "c3lYU2twT3lBTkNpQm1aQ0E5SUhOdlkydGxkQ2hCUmw5SlRrVlVMQ0JUVDBOTFgxTlVVa1ZCVFN3Z1NWQlFVazlVVDE5VVExQXBJRHNnRFFvZ2FXWWdLQ2hqYjI1dVpX" ascii /* base64 encoded string 'syXSkpOyANCiBmZCA9IHNvY2tldChBRl9JTkVULCBTT0NLX1NUUkVBTSwgSVBQUk9UT19UQ1ApIDsgDQogaWYgKChjb25uZW' */
      $s5 = "PSInLiR0aGlzYmcuJyIgb25tb3VzZW92ZXI9InRoaXMuY2xhc3NOYW1lPVwnZm9jdXNcJzsiIG9ubW91c2VvdXQ9InRoaXMuY2xhc3NOYW1lPVwnJy4kdGhpc2JnLidc" ascii /* base64 encoded string '="'.$thisbg.'" onmouseover="this.className=\'focus\';" onmouseout="this.className=\''.$thisbg.'\' */
      $s6 = "eXBlPSJoaWRkZW4iIC8+IDxpbnB1dCBuYW1lPSJyZSIgdmFsdWU9IjEiIHR5cGU9ImNoZWNrYm94IiAnLigkcmUgPyAnY2hlY2tlZCcgOiAnJykuJyAvPiBSZWd1bGFy" ascii /* base64 encoded string 'ype="hidden" /> <input name="re" value="1" type="checkbox" '.($re ? 'checked' : '').' /> Regular' */
      $s7 = "cHg7aGVpZ2h0OjUwcHg7b3ZlcmZsb3c6YXV0bzsiPicuaHRtbHNwZWNpYWxjaGFycygkc3FsX3F1ZXJ5LEVOVF9RVU9URVMpLic8L3RleHRhcmVhPjwvdGQ+PHRkIHN0" ascii /* base64 encoded string 'px;height:50px;overflow:auto;">'.htmlspecialchars($sql_query,ENT_QUOTES).'</textarea></td><td st' */
      $s8 = "MTI1MScsJ2NwMTI1NicsJ2NwMTI1NycsJ2NwODUwJywnY3A4NTInLCdjcDg2NicsJ2NwOTMyJywnZGVjOCcsJ2V1Yy1qcCcsJ2V1Yy1rcicsJ2diMjMxMicsJ2diaycs" ascii /* base64 encoded string '1251','cp1256','cp1257','cp850','cp852','cp866','cp932','dec8','euc-jp','euc-kr','gb2312','gbk',' */
      $s9 = "cz0iJy4kdGhpc2JnLiciIG9ubW91c2VvdmVyPSJ0aGlzLmNsYXNzTmFtZT1cJ2ZvY3VzXCc7IiBvbm1vdXNlb3V0PSJ0aGlzLmNsYXNzTmFtZT1cJycuJHRoaXNiZy4n" ascii /* base64 encoded string 's="'.$thisbg.'" onmouseover="this.className=\'focus\';" onmouseout="this.className=\''.$thisbg.'' */
      $s10 = "LigoJHJvd2RiWyRuYW1lXVsnS2V5J10gPT0gJ1VOSScgfHwgJHJvd2RiWyRuYW1lXVsnS2V5J10gPT0gJ1BSSScpID8gJzxiPiAtIFBSSU1BUlk8L2I+JyA6ICcnKS4o" ascii /* base64 encoded string '.(($rowdb[$name]['Key'] == 'UNI' || $rowdb[$name]['Key'] == 'PRI') ? '<b> - PRIMARY</b>' : '').(' */
      $s11 = "IHdpZHRoPSIxNiUiPkxhc3QgbW9kaWZpZWQ8L3RkPjx0ZCB3aWR0aD0iMTAlIj5TaXplPC90ZD48dGQgd2lkdGg9IjIwJSI+Q2htb2QgLyBQZXJtczwvdGQ+PHRkIHdp" ascii /* base64 encoded string ' width="16%">Last modified</td><td width="10%">Size</td><td width="20%">Chmod / Perms</td><td wi' */
      $s12 = "aW5zZXJ0c3FsWycuJHJvd1snRmllbGQnXS4nXSIgc3R5bGU9IndpZHRoOjUwMHB4O2hlaWdodDo2MHB4O292ZXJmbG93OmF1dG87Ij4nLiR2YWx1ZS4nPC90ZXh0YXJl" ascii /* base64 encoded string 'insertsql['.$row['Field'].']" style="width:500px;height:60px;overflow:auto;">'.$value.'</textare' */
      $s13 = "PjxhIGhyZWY9ImphdmFzY3JpcHQ6ZWRpdHJlY29yZChcJ2VkaXRcJywgXCcnLiR3aGVyZS4nXCcsIFwnJy4kdGFibGVuYW1lLidcJyk7Ij5FZGl0PC9hPiB8IDxhIGhy" ascii /* base64 encoded string '><a href="javascript:editrecord(\'edit\', \''.$where.'\', \''.$tablename.'\');">Edit</a> | <a hr' */
      $s14 = "dGg9IjIwMCIgYm9yZGVyPSIwIiBjZWxscGFkZGluZz0iMCIgY2VsbHNwYWNpbmc9IjAiPjx0cj48dGQgY29sc3Bhbj0iMiI+UnVuIFNRTCBxdWVyeS9xdWVyaWVzIG9u" ascii /* base64 encoded string 'th="200" border="0" cellpadding="0" cellspacing="0"><tr><td colspan="2">Run SQL query/queries on' */
      $s15 = "Jz0+J1BsZWFzZSBpbnB1dCBQSFAgY29uZmlndXJhdGlvbiBwYXJhbWV0ZXIoZWc6bWFnaWNfcXVvdGVzX2dwYyknLCduYW1lJz0+J3BocHZhcm5hbWUnLCd2YWx1ZSc9" ascii /* base64 encoded string ''=>'Please input PHP configuration parameter(eg:magic_quotes_gpc)','name'=>'phpvarname','value'=' */
      $s16 = "MjAwNC0yMDExIDxhIGhyZWY9Imh0dHA6Ly93d3cuNG5nZWwubmV0IiB0YXJnZXQ9Il9ibGFuayI+U2VjdXJpdHkgQW5nZWwgVGVhbSBbUzRUXTwvYT4gQWxsIFJpZ2h0" ascii /* base64 encoded string '2004-2011 <a href="http://www.4ngel.net" target="_blank">Security Angel Team [S4T]</a> All Right' */
      $s17 = "RCBCWSAnX19hbmdlbF97JHRpbWVzdGFtcH1fZW9mX18nIEVTQ0FQRUQgQlkgJycgTElORVMgVEVSTUlOQVRFRCBCWSAnX19hbmdlbF97JHRpbWVzdGFtcH1fZW9mX18n" ascii /* base64 encoded string 'D BY '__angel_{$timestamp}_eof__' ESCAPED BY '' LINES TERMINATED BY '__angel_{$timestamp}_eof__'' */
      $s18 = "J2dlb3N0ZDgnLCdncmVlaycsJ2hlYnJldycsJ2hwOCcsJ2tleWJjczInLCdrb2k4cicsJ2tvaTh1JywnbGF0aW4xJywnbGF0aW4yJywnbGF0aW41JywnbGF0aW43Jywn" ascii /* base64 encoded string ''geostd8','greek','hebrew','hp8','keybcs2','koi8r','koi8u','latin1','latin2','latin5','latin7','' */
      $s19 = "Jzs/Pjwvc3Bhbj48P3BocCBlY2hvICRfU0VSVkVSWydIVFRQX0hPU1QnXTs/PiAoPD9waHAgZWNobyBnZXRob3N0YnluYW1lKCRfU0VSVkVSWydTRVJWRVJfTkFNRSdd" ascii /* base64 encoded string '';?></span><?php echo $_SERVER['HTTP_HOST'];?> (<?php echo gethostbyname($_SERVER['SERVER_NAME']' */
      $s20 = "IGNsYXNzPSJidCIgbmFtZT0iZG91cGZpbGUiIHZhbHVlPSJVcGxvYWQiIHR5cGU9InN1Ym1pdCIgLz48aW5wdXQgbmFtZT0idXBsb2FkZGlyIiB2YWx1ZT0iJy4kbm93" ascii /* base64 encoded string ' class="bt" name="doupfile" value="Upload" type="submit" /><input name="uploaddir" value="'.$now' */
   condition:
      uint16(0) == 0x3f3c and filesize < 300KB and
      8 of them
}

rule lolipop_encoded26ced522_e33b_445e_8f16_6f6fbc9fa101 {
   meta:
      description = "php - file lolipop-encoded26ced522-e33b-445e-8f16-6f6fbc9fa101.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "32410d270593f47d256f9cdbd69cfc0f5d0caa8e9755e51aecadd9dad481f21f"
   strings:
      $s1 = "    |     Lolipop Web Shell - leetc0des.blogspot.com   |" fullword ascii
      $s2 = " goto v6Ugs; JcPpr: $Kc6LM = HbR85($I0cZf) or die(oSt4G()); goto PlROZ; DNlIV: $hMJKu = \"\\x3c\\146\\x6f\\156\\x74\\x20\\146\\1" ascii
      $s3 = "= ini_get(\"\\163\\x61\\146\\145\\x5f\\155\\x6f\\x64\\x65\"); goto LLbD7; TQfee: if (!(isset($_GET[\"\\x64\\x69\\162\"]) && is_d" ascii
      $s4 = "($VRlSM) && !empty($me2yV))) { goto QyBwW; } goto TIU6F; RdbkA: $tpV1S = $_POST[\"\\x6d\\171\\142\\x62\\144\\x62\\165\"]; goto l" ascii
      $s5 = "version(); goto KV0PR; g5Qim: $itZPf = $_POST[\"\\155\\x79\\x62\\142\\x69\\156\\x64\\x65\\x78\"]; goto iZKvl; zCFCq: echo \"\\74" ascii
      $s6 = "x70\\x69\\x6e\\146\\157\"])) { goto H0hK1; } goto hSwfP; DnB4T: $k0pmv = tempnam($qcweX, \"\\x63\\170\"); goto MrIXU; Z2FLb: ech" ascii
      $s7 = "\\x3a\\x29\\51\"; goto hreYX; l8hOt: $beXNb = $_POST[\"\\155\\x79\\142\\142\\x64\\x62\\x6e\"]; goto JGAmJ; QWKJ4: Oni10: goto go" ascii
      $s8 = "\\155\\146\\x64\\142\\x68\"]; goto xhktg; e9Qhw: $qkH0I = $_POST[\"\\x67\\x6f\\155\\153\\146\"]; goto RR6oo; IUS_h: T10iw: goto " ascii
      $s9 = "E3) or die(OSt4g()); goto OKSmz; dsN6T: error_reporting(0); goto jycgo; PXAKq: $FKq3R = php_uname(); goto VrDX8; NLRlT: QyBwW: g" ascii
      $s10 = "\\x4e\\157\\x6e\\145\\74\\57\\146\\x6f\\156\\164\\76\"; goto ocoeP; bv_GX: die; goto Xqjlq; UBgxO: $khoJc = $_POST[\"\\x70\\x68" ascii
      $s11 = " = $_SERVER[\"\\x53\\105\\122\\126\\105\\122\\x5f\\x41\\104\\104\\x52\"]; goto tn8pF; lNfm3: $WYZNu = $_POST[\"\\x74\\x75\\x73" ascii
      $s12 = "150\\157\\x20\\42{$S1C0u}\\42\\x3b\"); goto zAdeG; NCF3X: Cski4($bc22f) or die(oST4g()); goto MhCER; RR6oo: $kjOnO = $_POST[\"" ascii
      $s13 = " hsjUn; } goto jA9qD; Xqjlq: GGAmv: goto WCGwu; dbtUd: $kDJbW = realpath($_GET[\"\\x63\\150\\144\\x69\\x72\"]) . \"\\x2f\"; goto" ascii
      $s14 = "\"]; goto S8TAI; Kao0J: f4qN3: goto Ssef1; oet3m: if ('' == $XsN2A) { goto Oni10; } goto PFeo_; PldM6: $cgx2Z = $_POST[\"\\x73" ascii
      $s15 = "o uGZTL; jbYdB: $jidLo = $_POST[\"\\x65\\x78\\x65\\x63\\165\\164\\x65\"]; goto lxgp6; WZwKe: $cz3Kw = $_POST[\"\\x64\\x62\\165\"" ascii
      $s16 = "oto W26kh; kn1o9: $FBsgM = $_POST[\"\\163\\x62\\x6a\\x63\\x74\"]; goto oOP4n; oOP4n: $AtXKh = $_POST[\"\\x6d\\x73\\147\"]; goto " ascii
      $s17 = "bR85($e1M26) or die(OST4G()); goto IQL9m; TLcYz: if (!isset($_POST[\"\\166\\x62\\165\\154\\x6c\\145\\164\\151\\x6e\"])) { goto G" ascii
      $s18 = "3CW5; S8TAI: $sEmWH = $_POST[\"\\x70\\150\\160\\142\\142\\144\\x62\\165\"]; goto UBgxO; ssvoY: $kwfAj = \"\\x46\\x72\\x6f\\155" ascii
      $s19 = "[\"\\x66\\144\\x65\\x6c\"]; goto jbYdB; LLbD7: $XsN2A = ini_get(\"\\x64\\151\\x73\\141\\x62\\154\\x65\\137\\x66\\165\\x6e\\143" ascii
      $s20 = "OST[\"\\x64\\142\\x68\"]; goto WZwKe; XkIvb: if (!isset($_POST[\"\\x73\\155\\x66\"])) { goto kJAYB; } goto IaH5w; lM0lA: $PYjDn " ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      8 of them
}

rule hector_uploader3efd02fe_1e7b_4fa2_a494_1f8e505e1eb2 {
   meta:
      description = "php - file hector-uploader3efd02fe-1e7b-4fa2-a494-1f8e505e1eb2.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "e694b3ba6150a49fd588f76fda0c872ac43e383967623411283ac93ed9a2ac0a"
   strings:
      $s1 = "yZjl3YmNWcDI3RW82SFlYU3N1akNKTU5La1AweFRSMXlkaDVCQWx2RFUrcUdpRm5PZ3R6PScsJ0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5" ascii /* base64 encoded string 'f9wbcVp27Eo6HYXSsujCJMNKkP0xTR1ydh5BAlvDU+qGiFnOgtz=','ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn' */
      $s2 = "wMCgkTzAwME8wTzAwLDB4NTRiKTskT08wME8wME8wPSRPT08wMDAwTzAoJE9PTzAwMDAwTygkTzBPMDBPTzAwKCRPMDAwTzBPMDAsMHgxN2MpLCdhM21MZS84SVdRNFp" ascii /* base64 encoded string '0($O000O0O00,0x54b);$OO00O00O0=$OOO0000O0($OOO00000O($O0O00OO00($O000O0O00,0x17c),'a3mLe/8IWQ4Z' */
      $s3 = "e7pElQhHosPYEAkWkUXWPiJXE2MoVKnmMcPYEAkWLDCQ/g8V2A/2UyMXP7qHPkyHVQsElQh6EUkWkDnmP7NY8OCWNAJW8JlHE6gomWKHPkyH7BMwMcPYEAkwmgJwMWnm" ascii
      $s4 = "0ckX0bd7IkBHVWC6+ghs87hsLDMs87Gsmgxs8Uy9l3NY8/lS+7DwosTXPc5sqrdsocPZpCMwCD4wIcTs8Akw07DHNB5s8kDX82tLbxOZ+Jk6EbtLbxO6PgKupGfmMSnm" ascii
      $s5 = "N/YuPg0VKJVY8fdH8AKbDQTH7f3Y+cdXITJE/Q+6+k3sekL2N/NrkHiV2rBHDTWbPJNrDUTpqSBVDkLb03YY2/5V7sEs8fW2N7ZbUWvEksQSedpbNsQc2QDE7sySDdLV" ascii
      $s6 = "03NrPBBEokvSKgibNke2o336vQEr/Kl9oHJrPAyVDf4rP/6p03KV8gTpefVrP/6p03KcDUBpqSgwVWnmP7+6EBxQesrpDQ3p/fXQDkQV2kQV2kQV2KAXmss4mcQV2kQV" ascii
      $s7 = "2kQVEAyQUDx4VadrpaUrv6BfNCG9BxKcDAwbK/r2Uy0V2kQV2kQV2kQVEBAQUDxQ8iks+HTX82yQekQV2kQV2kQV2kyVVKnmMcQV2kQV2kQV2kQr2KCwVaMVKJYS8rlX" ascii
      $s8 = "DgwreOBpvaBZMW0WMBKpDgwrLaBreOB4mcwpDOBrLaBreOxQeOBpvaBpDOBrmCKpvaBreOBpvaBZmcwpvaBpvaBrLaTZmsJr+UrHVOGV7scf/TlHNkq6PfESLWqcEO+V" ascii
      $s9 = "L3Hu2eiV2fVHkeB973pr8A87qk4rP/6p03KVeUTE/cvpKfdX8UQb+s1H8UyuP/62PTQcLaiV2fQY2dpbNse2Eg0V2fVrP/6p03KcDU0V2bBHDUeSDiLY2/0VKJYS8rlX" ascii
      $s10 = "/k62qfUYKf4p2iZYUaBu/cVrokKYL7mbEA+c/21S2sTcPiwHqcFwVSyQD/mbDc/cKsWV2TZpeU9pU3c2kf277HoE/kY6EQNH87PH+JTYPdyXEi5SI/lSqcUs0sGuoxBr" ascii
      $s11 = "vse2Eg0V2fVSEco2N/MbD/0V2bBHDkRcpfwbv/L6Ks8YP/ibPgKV/Qqp+KGsKTW2PJNXEcyHefmYE7pbEdKXEAF67JVsPfTVpse2Eg0V2fVYEWl2N7QbD/0V2bBHDk1V" ascii
      $s12 = "0UkXIfkWIy4HEfxXlCMHEUBsIKM4py4jbxKXP7qHPkyHVagWmcj2D7V7K7VEUfL2Kkb7/g8V2A/pK/fc7DnmMcQV2kQV2kQV2kQXeKCwVaKcDAwbK/r2Uy0V2kQV2kQV" ascii
      $s13 = "/AhWNy4HEfxXlaMw8khSI7DWIciS82gomQvsEQdYocSWM3+6EAUHpUSWKgZomWtw8QlwkAhWNy4HEfxXlaMwmgPXqQdwkAhWNy4YE6xQesrpDQ3p/fXQDkQV2kQV2kQV" ascii
      $s14 = "PgHEeT1HLQ8u7ToY8AHE/Ty6PKUYPWlr2/YrN/x67sqs7Kl9ocQYos16EiEY+cosqf4cDT+EKJ1SDTW70TYEekvVKJmY8rvpo3wu2Wic//B92ccS8AMVeiyV2JvHDTWE" ascii
      $s15 = "LUSW035SqcSWM3kXPfDuo3kw7BMXo7ys8kB6oQDZ+H5SPDdH8/D67BMwkAhWNy4HEfxXlaMw8khSI7DWIciS82gomQPYEAkomWCXP/dHpUSWPiks+HTX87SWNGO60WtW" ascii
      $s16 = "03MXEg0V2f3HDker8s4cNk22kH47UQEVPQQXeT877HEck2A2PHE7KT4VEBBfDccX+sQbUWBE7J4XkT62EsQcL306+U8r+c6V0fYcUHR6NQVXedL2NfY7DkUVKsysE/TY" ascii
      $s17 = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
      $s18 = "2kQVVss4mcjcKkrc7fXWPiks+HTX82Mo7yMs8UBo+iJXE2MoVKTm0y4XEg+H7gUS8A56EckH/gPYEAk4mcjcKkrc7fXWPiks+HTX82Mo7yMs8UBo+iJXE2MoVBKoDHQp" ascii
      $s19 = "SUlJSUlJSUlsMT0ndG91Y2gnOyRJSUlJSUlJSUlJbGw9J3RpbWUnOyRJSUlJSUlJSUlJSUk9J2lzX3VwbG9hZGVkX2ZpbGUnOw==')); ?><?php /* xorro@jabber" ascii
      $s20 = "P7NY8OCWNAxrpiWc2f2pUWC773rpD/ec7WOZ+CAwkAhWNy4HEfxXlaMV7aFWmWnmP7NY8OCQ/gpc7QEc7QXQUQ/p2g2c7g3cecVQUDnmP7NY8OCWNAPXqQdW8Uks8J5H" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 10KB and
      8 of them
}

rule nobody_uploader75ccbc89_d53f_4273_89e2_99cf7ab48a01 {
   meta:
      description = "php - file nobody-uploader75ccbc89-d53f-4273-89e2-99cf7ab48a01.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "2ff89778dded2a5a2d38b28b8f1f6e23bb9f70be562d2c089af757daae3d0548"
   strings:
      $s1 = "yZjl3YmNWcDI3RW82SFlYU3N1akNKTU5La1AweFRSMXlkaDVCQWx2RFUrcUdpRm5PZ3R6PScsJ0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5" ascii /* base64 encoded string 'f9wbcVp27Eo6HYXSsujCJMNKkP0xTR1ydh5BAlvDU+qGiFnOgtz=','ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn' */
      $s2 = "wMCgkTzAwME8wTzAwLDB4NTU2KTskT08wME8wME8wPSRPT08wMDAwTzAoJE9PTzAwMDAwTygkTzBPMDBPTzAwKCRPMDAwTzBPMDAsMHgxN2MpLCdhM21MZS84SVdRNFp" ascii /* base64 encoded string '0($O000O0O00,0x556);$OO00O00O0=$OOO0000O0($OOO00000O($O0O00OO00($O000O0O00,0x17c),'a3mLe/8IWQ4Z' */
      $s3 = "YEAk4mcjcKkrc7fXWPiks+HTX82Mo7yMs8UBo+iJXE2MoVBKoDHQpe7pElQhHosPYEAkWkUXWPiJXE2MoVKnmMcPYEAkWLDCQ/g8V2A/2UyMXP7qHPkyHVQsElQh6EUk" ascii
      $s4 = "pK/fc7DnmMcDYEUkWLDCQesrpDQ3p/fXQDkQV2kQV2kQV2kyXmss4mKCZpeBfpr+rL6G9Ly4QesrpDQ3p/fXQDkQV2kQV2kQV2kyrVss4mchHosPYEAkZmcDYEUk4py4" ascii
      $s5 = "Xla0w8JDXEBtLbxOY87JHLGfmNAdHocJW8JDsIadHo/UYo6gWKf5X0ckX0bd7IkBHVWC6+ghs87hsLDMs87Gsmgxs8Uy9l3NY8/lS+7DwosTXPc5sqrdsocPZpCMwCD4" ascii
      $s6 = "WkDnmP7NY8OCWNAJW8JlHE6gomWKHPkyH7BMwMcPYEAkwmgJwMWnm0UkXIfkWIy4HEfxXlCMHEUBsIKM4py4jbxKXP7qHPkyHVagWmcj2D7V7K7VEUfL2Kkb7/g8V2A/" ascii
      $s7 = "QekQV2kQV2kQV2KAVVagWmQ4V/TB6vQyr/kibpkQbUQP2pai2/rBXeHou2xl67J9S8cWpEk67IfZ67sHHDdL2NQJEeiBHesfHU32r8sQY2kBV2JvVDkLbEdKXEAF67JV" ascii
      $s8 = "QegwrL3wrL3wrLUvsIQjSP7BX8/NHVC0oUg8V2A/oUO0ZmW0WMGKpDgwreOBpvaBZMW0WMBKpDgwrLaBreOB4mcwpDOBrLaBreOxQeOBpvaBpDOBrmCKpvaBreOBpvaB" ascii
      $s9 = "Y+7pbEsQbDeiV2f4b+co6vHQbUWBE7J4XkT62EsHXPd0VKJYS8rlXL3MrDk0p/f3Y+c6pPANY2/DV2fVY8c62Pg6rDQx6vffY2gqX+sQc+AdV2f0Y/TorosKV8d5VKJK" ascii
      $s10 = "uKd2S+sP2oaib+UES+rl7Esku2/1H8UyuP/62PTZuorqV2CBVU/WpPAKcDi+6NQDS/TpH+kKXEAF67JVfKkTs+dKXEAF67JVYKd2SvDM9BTksP/y4mcIpegmb2ApElsQ" ascii
      $s11 = "ZmcwpvaBpvaBrLaTZmsJr+UrHVOGV7scf/TlHNkq6PfESLWqcEO+V/k62qfUYKf4p2iZYUaBu/cVrokKYL7mbEA+c/21S2sTcPiwHqcFwVSyQD/mbDc/cKsWV2TZpeU9" ascii
      $s12 = "YKkLbpkQceeqb+k3HDTWE03NrPBB6NfQHU3pbEd6r2i87EAYck7yS+k7YUH97L/VckCBcK7VcKkTE/cvVDkLbEdKrkHTV2f3HDkLbpkQbUQP7p3E2UH17kfou2TQ7KHV" ascii
      $s13 = "27CBY/37r7/TE/cvVDkLbEdJ7v7AV2f3HDkLbpkQbUQP7p3E2UH17kfou2Tp2kH87kQEpk76r7Hp2Uf4HegqX+sQbUWBE7J4XkT62EsQcL306+U8r+c6V0fYcUHR6NQV" ascii
      $s14 = "c7QEc7QXQUQ/p2g2c7g3cecVQUDnmP7NY8OCWNAPXqQdW8Uks8J5HLUSW035SqcSWM3kXPfDuo3kw7BMXo7ys8kB6oQDZ+H5SPDdH8/D67BMwkAhWNy4HEfxXlaMw8kh" ascii
      $s15 = "XedL2NfY7DkUVKsysE/TYvsLY2/0VKsBr7TW70fQbD/02/f3Y2U26vcr72TvE7s9SKkIYL3KVee+pIKGY+cIc0kYrk6BV2s4f2kL2NQJEeiBHeSiu2kRSDdQbD/1EEDi" ascii
      $s16 = "SI7DWIciS82gomQPYEAkomWCXP/dHpUSWPiks+HTX87SWNGO60WtW/AhWNy4HEfxXlaMw8khSI7DWIciS82gomQvsEQdYocSWM3+6EAUHpUSWKgZomWtw8QlwkAhWNy4" ascii
      $s17 = "X/kTYq3QVIf022SAY8/os+gQXEJx6+UVrUk6VPAJcUHxH8UEs2Adp0HM72Qh6ks8S8QLfETMrN3TpefVSEco2N/Mbqs1EEDiY+7ps+dKEeiy6+kqYUk67N3JcNkqE7J9" ascii
      $s18 = "HEfxXlaMwmgPXqQdwkAhWNy4YE6xQesrpDQ3p/fXQDkQV2kQV2kQV2kQVVss4mcjcKkrc7fXWPiks+HTX82Mo7yMs8UBo+iJXE2MoVKTm0y4XEg+H7gUS8A56EckH/gP" ascii
      $s19 = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
      $s20 = "QegwrL3wrL3wrLUvsIQjSP7BX8/NHVC0oUg8V2A/oUO0ZmW0WMGKpDgwreOBpvaBZMW0WMBKpDgwrLaBreOB4mcwpDOBrLaBreOxQeOBpvaBpDOBrmCKpvaBreOBpvaB" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 10KB and
      8 of them
}

rule Votr_shelld1d05425_fcf8_4bfb_9c8c_386f276ca4bb {
   meta:
      description = "php - file Votr shelld1d05425-fcf8-4bfb-9c8c-386f276ca4bb.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "1b258e392a903cb68c2e56084b93a9a7220e696ab2c50fbd44ecc6267f582858"
   strings:
      $s1 = "ase64_decode(\"7\\x623rW\\x74\\x76I\\x30jD\\x36O/\\x4d8\\x75\\x59\\x65\\x4f\\x68h\\x58B\\x69\\x76EJ\\x79\\x41Fi\\x54zg\\x6d\\x4a" ascii
      $s2 = "\\x49S\\x68Z\\x36UE\\x4aH3Eylef7q\\x49\\x6fSU\\x75\\x53\\x70eB\\x551i\\x74y\\x51v+\\x6c\\x32\\x6brS\\x4f\\x53\\x70w\\x74\\x699N" ascii
      $s3 = "\\x36/\\x58/\\x63\\x50xyrvK9Ur\\x76+lvnt3\\x4c\\x766+\\x58\\x72\\x67+v\\x57\\x62\\x33v\\x32\\x6f\\x30e\\x64q\\x72\\x31\\x69\\x6c" ascii
      $s4 = "\\x5aSi\\x45WAn\\x5a\\x6b\\x34\\x6c\\x78\\x6fiWj\\x30\\x77ZPl\\x58\\x65\\x6a\\x61\\x69\\x7ad\\x44Rx\\x6e\\x6b\\x4dvndH9\\x69\\x6" ascii
      $s5 = "\\x53\\x42N\\x36\\x57l\\x50u4\\x75\\x6dn\\x6e\\x311rK\\x51\\x4dz\\x5804\\x6fUY\\x4e9E\\x69\\x57\\x386HR6\\x30v+\\x43\\x50yTlNe" ascii
      $s6 = "\\x34\\x30\\x38fpw\\x46\\x39+QM\\x5aI\\x55\\x41\\x4d\\x47\\x45\\x584VQ\\x6c\\x4cRa\\x4ekTOY\\x4aQD\\x75GX\\x54\\x510\\x41\\x52K" ascii
      $s7 = "\\x61my\\x65X\\x62uX\\x54\\x7a\\x59fhhfOdc\\x31ab\\x56\\x6dPQU\\x4691\\x6d\\x6b/WW\\x6c3\\x6e\\x6a6\\x38rF0+X\\x57\\x49\\x6f\\x5" ascii
      $s8 = "\\x70\\x50T\\x65\\x52J\\x5a\\x32\\x64\\x4b1Wk\\x51\\x65z\\x73\\x4ct\\x57N\\x77D\\x52iA\\x4eiF\\x63nnmY\\x54Ox5\\x42\\x6a\\x38\\x" ascii
      $s9 = "\\x74\\x4c\\x39\\x33/6\\x58\\x56\\x77DYT\\x35v1Rtj\\x74u\\x566XV\\x636\\x49proo9K\\x6b\\x61\\x31wWl4\\x6fmJ\\x5ada\\x74PAVdWi\\x" ascii
      $s10 = "\\x44S\\x57O\\x56\\x75X\\x77\\x67uUel\\x69DK\\x74ob\\x33N/YO\\x6aQwp2\\x4c\\x54o\\x694\\x35\\x42\\x6b\\x4ep\\x4cQ\\x54\\x55+k\\x" ascii
      $s11 = "\\x4eOx\\x34G+57\\x51\\x32\\x36\\x50NOK\\x30B\\x66\\x65yoW\\x39P\\x55n\\x6f\\x77E\\x6c\\x6b\\x42u\\x6dt\\x57GFUx\\x73gV\\x6bmX" ascii
      $s12 = "\\x4e\\x54L\\x33\\x73\\x75bbY\\x44q\\x54\\x43+sgSW\\x42\\x4cC\\x36y4\\x4a\\x57W\\x48o\\x6cXDdB\\x53\\x67YGoB\\x69F\\x740\\x70xoS" ascii
      $s13 = "\\x78N6qYbE\\x75L\\x31\\x4bV3KBWiK\\x79kKfkgSuO+2j\\x6b\\x37\\x47\\x35\\x54c\\x76u\\x7a\\x36\\x4f1cP\\x47\\x57\\x57/\\x33\\x72" ascii
      $s14 = "\\x77j\\x57\\x66\\x4bZJUQu\\x74\\x61\\x46hQ\\x7a8x\\x52\\x38\\x46n\\x50cgCf7tWB\\x63\\x6a\\x4c7\\x4c\\x43B\\x43sM\\x6eWj\\x55FWm" ascii
      $s15 = "\\x6e\\x79F\\x64\\x49\\x31\\x52\\x34aR\\x5a\\x63N2C\\x46u\\x4foJa\\x4f\\x6aF\\x73I\\x67WNDdT\\x56A\\x6c\\x57\\x31\\x4e\\x6di\\x4" ascii
      $s16 = "\\x79\\x77\\x77\\x52jUh\\x61w\\x65\\x45j\\x47\\x5aoX\\x54rkh6/Mg\\x41ui/L\\x52dTgl\\x53b\\x6e\\x4f\\x53r\\x71\\x58pXD\\x77b9\\x4" ascii
      $s17 = "\\x37\\x73w\\x59qL\\x6bXD\\x4dx/y\\x571\\x59\\x78\\x41\\x5a8\\x67\\x77\\x62\\x4dG\\x33\\x52\\x7007\\x75XWQ7\\x37\\x61\\x72KG\\x6" ascii
      $s18 = "\\x36l48BMQc\\x31\\x6f2\\x72UN5\\x46D2\\x52\\x34ZvZ\\x36\\x58\\x6fl7\\x79Yr\\x75gr\\x391\\x4c\\x6dbyv\\x55tx\\x72\\x4e/R\\x38N" ascii
      $s19 = "\\x41\\x4f\\x36\\x72\\x63\\x42OP\\x76\\x6e/\\x59\\x56Un\\x34\\x47\\x35Cw\\x6b1\\x49M\\x5aVI\\x4eY\\x4c\\x5aikF\\x38Q6\\x77SSlI" ascii
      $s20 = "\\x55\\x34t\\x4f9W\\x64I\\x6cy\\x4fIOZ\\x55\\x66\\x63Y\\x62\\x50\\x56V\\x76gb\\x78YV\\x6dY/\\x63E\\x6c\\x4bZP\\x35s\\x6eu2\\x36P" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 300KB and
      8 of them
}

rule SHOR7CUTShellBETAKILLERencoded1421a1ab_142a_4e8b_b41e_eb50b697c517 {
   meta:
      description = "php - file SHOR7CUTShellBETAKILLERencoded1421a1ab-142a-4e8b-b41e-eb50b697c517.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "99fc39a12856cc1a42bb7f90ffc9fe0a5339838b54a63e8f00aa98961c900618"
   strings:
      $s1 = "    |     Shor7cut Shell  - leetc0des.blogspot.com     |" fullword ascii
      $s2 = " goto AXn2z; Xm2l4: echo $akJ2b . \"\\133\\x61\\144\\x64\\40\\154\\157\\x63\\141\\x6c\\147\\x72\\x6f\\165\\x70\\135\\x2d\\76\\x2" ascii
      $s3 = "o \"\\x3c\\x70\\162\\x65\\76\" . shell_exec(\"{$e1mct}\"); goto BgBQ2; Pe0yt: if (!$_POST[\"\\163\\x75\\x62\\155\\x69\\x74\"]) {" ascii
      $s4 = "\\x20\\57\\x61\\x64\\x64\"); goto BJ8b8; QAcQG: $N3LLO = shell_exec(pWsQk); goto x27KO; pFQ4W: xg8Fo: goto OtSGD; uoRmk: $Smitg " ascii
      $s5 = "Oguxi: $j1_Kq = shell_exec(\"\\156\\x65\\164\\40\\154\\157\\x63\\x61\\x6c\\147\\x72\\x6f\\165\\160\\40\\x41\\x64\\155\\x69\\156" ascii
      $s6 = "R; goto YlqN5; EYGiz: $w0Lww = shell_exec(\"\\156\\x65\\x74\\x20\\154\\157\\143\\141\\154\\147\\162\\x6f\\x75\\160\\40\\101\\x64" ascii
      $s7 = "goto FR63T; ZOQy7: goto vOvqv; goto Pzc_8; uT3mp: goto OmiZu; goto vimNj; dCXDx: $I7S3j = shell_exec(\"\\156\\145\\164\\x20\\x75" ascii
      $s8 = "57\\167\\x27\\76\\102\\145\\x72\\x68\\141\\163\\151\\154\\74\\x2f\\146\\x6f\\x6e\\164\\76\" . $aXXsB; goto bmig1; BJ8b8: $mrUS1 " ascii
      $s9 = "x73\\151\"] == \"\\63\")) { goto y_uK3; } goto rDulV; jml58: $PmfAp = shell_exec(\"\\156\\145\\164\\40\\165\\x73\\145\\162\\x20" ascii
      $s10 = "OEK: h4K1J: goto anIv_; FC91T: HjtA9: goto HoClF; n7mYZ: shell_exec(\"\\x73\\150\\x75\\164\\144\\157\\x77\\156\\x20\\55\\x73\\40" ascii
      $s11 = " goto roVsW; Ufwyk: sleep(1); goto mtG2e; ODUSs: $PmfAp = shell_exec(\"\\156\\145\\x74\\x20\\165\\x73\\x65\\x72\\x20\" . $ymDji " ascii
      $s12 = "6f\\141\\x64\"] == \"\\63\")) { goto XkgT2; } goto H2J4i; ViEY4: qJhjg: goto X71u1; muDhI: $Ewxlp = shell_exec(\"\\156\\145\\164" ascii
      $s13 = "jS: echo \"\\x3c\\160\\x72\\145\\x3e\" . shell_exec(\"\\x6e\\145\\164\\x20\\x75\\163\\x65\\x72\"); goto VzfZM; AJJAa: UE7Us: got" ascii
      $s14 = "Ap = shell_exec(\"\\156\\145\\164\\40\\165\\x73\\145\\x72\\x20\" . $ymDji . \"\\40\\57\\104\\105\\114\\105\\124\\x45\"); goto lN" ascii
      $s15 = "RVER[\"\\123\\105\\122\\x56\\105\\122\\137\\116\\x41\\115\\x45\"]; goto epHRd; uiv34: $I7S3j = shell_exec(\"\\x6e\\x65\\x74\\x20" ascii
      $s16 = "t; CkKuF: $g9iTV = shell_exec(\"\\156\\x65\\164\\x20\\154\\x6f\\143\\141\\x6c\\x67\\162\\x6f\\x75\\x70\\40\\101\\144\\155\\x69" ascii
      $s17 = "1\"); goto dNl2S; tcQMA: $QaqrM = shell_exec(\"\\156\\145\\164\\40\\x6c\\157\\143\\x61\\154\\147\\162\\x6f\\165\\x70\\40\\101\\x" ascii
      $s18 = "63\\x69\\40\" . $pLUPj; goto cuIcU; xpWEy: neiZI: goto sg3BS; KEEQm: error_reporting(0); goto xIwdg; X031V: if (!($_POST[\"\\141" ascii
      $s19 = "oY1: goto EfRgV; goto ozFKA; sHzM3: n_96v: goto R8dwD; epHRd: $TwOZx = file_get_contents(\"\\x68\\164\\x74\\160\\72\\57\\57\\x77" ascii
      $s20 = "; wYZsM: $TwOZx = file_get_contents(\"\\150\\164\\x74\\x70\\x3a\\x2f\\57\\x77\\167\\x77\\x2e\\x74\\x65\\x6c\\x69\\x7a\\x65\\x2e" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      8 of them
}

rule fd9f3e2a_5094_4025_9856_acd7a22c52bf {
   meta:
      description = "php - file 类fd9f3e2a-5094-4025-9856-acd7a22c52bf.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "637a54c4184d48dc480a322a3b4b7901d34f12edffc76a1bdaa0224168cd0ac7"
   strings:
      $s1 = "header('HTTP/1.1 404 Not Found');" fullword ascii
      $s2 = "@eval($_.'//');" fullword ascii
      $s3 = "function __construct($_){" fullword ascii
      $s4 = "$t = new _(@${('$'^'{').'PO'.'ST'}['a']);" fullword ascii
      $s5 = "class _{" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule bd7db3fc_1ed0_49ac_8799_1041fba6f914 {
   meta:
      description = "php - file 函数bd7db3fc-1ed0-49ac-8799-1041fba6f914.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "ad423c0eb89c9b6c68b45069890d428a87017fb471961e2d63a0834565efd7eb"
   strings:
      $s1 = "header('HTTP/1.1 404 Not Found');" fullword ascii
      $s2 = "@eval($_.'//');" fullword ascii
      $s3 = "function _($_){" fullword ascii
      $s4 = "_(@${('$'^'{').'P'.'OST'}['a']);" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}



rule SimShell1_0_SimorghSecurityMGZ_encoded0a9cee12_abb6_42c6_851e_b85cfba0557e {
   meta:
      description = "php - file SimShell1.0-SimorghSecurityMGZ-encoded0a9cee12-abb6-42c6-851e-b85cfba0557e.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "883f48ed4e9646da078cabf6b8b4946d9f199660262502650f76450ecf60ddd5"
   strings:
      $s1 = "    |     Sim Shell 1.0   - leetc0des.blogspot.com     |" fullword ascii
      $s2 = " goto VNaHs; JBNMf: goto p0Er3; goto V7evB; VZPki: goto pZBlj; goto hb69f; Yfgcz: $_SESSION[\"\\157\\165\\164\\160\\165\\164\"] " ascii
      $s3 = "_REQUEST[\"\\162\\x6f\\x77\\163\"] + 1 - $n2fKT)); goto NtEQx; JoV91: goto UAPgF; goto oOcd9; jGAai: $n2fKT = substr_count($_SES" ascii
      $s4 = "lqQG; GxmHY: lv0gQ: goto vqz0P; zhJL3: $_SESSION[\"\\x6f\\x75\\164\\160\\x75\\164\"] .= htmlspecialchars(fgets($ch28z[2]), ENT_C" ascii
      $s5 = "164\"] .= htmlspecialchars(fgets($ch28z[1]), ENT_COMPAT, \"\\125\\x54\\106\\x2d\\70\"); goto v635H; F5F41: fclose($ch28z[2]); go" ascii
      $s6 = "nd5T: $_SESSION[\"\\143\\x77\\144\"] = $m83YY; goto NZj8u; BhGqj: $_SESSION[\"\\x63\\x77\\x64\"] = getcwd(); goto sCd0W; fNsAR: " ascii
      $s7 = "\\155\\155\\x61\\x6e\\144\"]); goto Yfgcz; hb69f: lzRXq: goto fXk7g; kR3yu: echo $c_9Ic; goto Uw7gZ; oY2PN: if (!get_magic_quote" ascii
      $s8 = ")) { goto ZwIfy; } goto r60Yf; ACfe4: header(\"\\x43\\157\\x6e\\x74\\145\\x6e\\x74\\x2d\\x54\\171\\160\\145\\x3a\\x20\\164\\x65" ascii
      $s9 = "\\56\\x29\\174\", $m83YY)) { goto IOSxS; } goto M8QXN; U9FNI: session_start(); goto Nr21f; fKxJQ: $m83YY = str_replace(\"\\57\\5" ascii
      $s10 = "\\x20\" . $_REQUEST[\"\\143\\157\\155\\x6d\\141\\156\\144\"] . \"\\xa\"; goto CdlHH; QV6Kc: chdir($_SESSION[\"\\143\\167\\x64\"]" ascii
      $s11 = "\\x73\\x6c\\x61\\x73\\x68\\x65\\x73\", $_SESSION[\"\\x68\\151\\x73\\x74\\x6f\\x72\\x79\"]); goto EC8Uh; V7evB: WyJgk: goto LfYtH" ascii
      $s12 = "2\\x6f\\x77\\163\\42\\40\\166\\x61\\x6c\\165\\145\\75\\42\"; goto Nw8Ct; coYeD: $_SESSION[\"\\x6f\\x75\\x74\\x70\\165\\164\"] = " ascii
      $s13 = "7\\162\\72\\x20\\x23\\x30\\60\\60\\x30\\x30\\60\\x22\\76\\xa\"; goto jGAai; OLBCs: fSBNO: goto zFJbJ; sCd0W: $_SESSION[\"\\x68" ascii
      $s14 = "pty($_SESSION[\"\\143\\167\\x64\"]) || !empty($_REQUEST[\"\\162\\x65\\163\\145\\x74\"]))) { goto aVVis; } goto BhGqj; tlqQG: ech" ascii
      $s15 = "w2i: $m83YY = $_SESSION[\"\\x63\\167\\x64\"] . \"\\57\" . $ObnwE[1]; goto MIs3j; r60Yf: $_REQUEST[\"\\x63\\157\\x6d\\x6d\\x61\\x" ascii
      $s16 = "4\"], $_SESSION[\"\\x68\\151\\x73\\164\\157\\x72\\171\"])) !== false)) { goto jTlLc; } goto WrlLc; Gol_X: $_SESSION[\"\\157\\x75" ascii
      $s17 = "\")), $ch28z); goto Nz558; WrlLc: unset($_SESSION[\"\\150\\151\\x73\\x74\\157\\162\\171\"][$P6Wxc]); goto yaSgx; aaD11: xknVm: g" ascii
      $s18 = "x21\\x5c\\56\\51\\174\", '', $m83YY); goto T2X5e; YGiw5: array_unshift($_SESSION[\"\\150\\151\\x73\\164\\157\\162\\171\"], $_REQ" ascii
      $s19 = "trcspn($_REQUEST[\"\\x63\\157\\x6d\\155\\x61\\x6e\\144\"], \"\\x20\\x9\"); goto i8c2o; o5NJr: $_SESSION[\"\\x6f\\x75\\x74\\x70" ascii
      $s20 = " IyvOQ: p0DbN: goto oqsg8; Nw8Ct: echo $_REQUEST[\"\\162\\x6f\\x77\\x73\"]; goto aX20E; NtEQx: echo rtrim($qLT5V . $_SESSION[\"" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 50KB and
      8 of them
}

rule G_Security_Webshell51f58cfa_acaf_4aff_86f9_6b075c91133d {
   meta:
      description = "php - file G-Security-Webshell51f58cfa-acaf-4aff-86f9-6b075c91133d.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "f35719c4ddc17ca19ba8def116741d0b15bcd433435ed21f41249ad3a87477ec"
   strings:
      $s1 = "wMDBPME8wMD0kT09PMDAwTzAwKCRPT08wTzBPMDAsJ3JiJyk7JE8wTzAwT08wMCgkTzAwME8wTzAwLDB4NTBlKTskT08wME8wME8wPSRPT08wMDAwTzAoJE9PTzAwMDA" ascii /* base64 encoded string '00O0O00=$OOO000O00($OOO0O0O00,'rb');$O0O00OO00($O000O0O00,0x50e);$OO00O00O0=$OOO0000O0($OOO0000' */
      $s2 = "wTygkTzBPMDBPTzAwKCRPMDAwTzBPMDAsMHgxN2MpLCdhM21MZS84SVdRNFpyZjl3YmNWcDI3RW82SFlYU3N1akNKTU5La1AweFRSMXlkaDVCQWx2RFUrcUdpRm5PZ3R" ascii /* base64 encoded string 'O($O0O00OO00($O000O0O00,0x17c),'a3mLe/8IWQ4Zrf9wbcVp27Eo6HYXSsujCJMNKkP0xTR1ydh5BAlvDU+qGiFnOgt' */
      $s3 = "bMopynHEfxXla0QvdTHMCK6+UKWmegWmWM4V3BSPkhsmaKcDAwbK/r2Uy0V2kQV2kQV2kQV2kyQUDxQ8fdHmKn9+7NY8OCQvB5SIQkwCD4wmgPXqQdwCD4wmgMX+ciwC" ascii
      $s4 = "aK6+UK9+7NY8OCQlWCLbTvsIkyHpDM6P/NY+slXq7hHLxNrLaBrLaB9+f5X8gl9MfPHPHPHP6nWNGfmNAxSNGfmNABSP2tLbx09lcNXEbCwVaKoUQ/277/2UcXWMUNXE" ascii
      $s5 = "sxEkSAs+cWY+g4V8cyEEk1SekWS+sccv/x67sqXDkdY8JNX7WvE7J4X8/I7PJKX7HUp8U9sPQ7bPiM7DHB6KrUYPWlr8krbUQAH/sVrEQLs+dHXpk1H7fqY+c6pPANYo" ascii
      $s6 = "s1E7JEr8/89osHEeiFVUcvH+HcSLkLX7Hv6vQ7H+7ibEdKXEAF67JVYKdiSvsQVL3Z22J9X8cIp0HMr0cBEkf0YEcdXITJE/W+VEkqY+cdXITJE/QRVUcvwVWnmP7+6E" ascii
      $s7 = "CKpvaBreOBpvaBZmcwpvaBpvaBrLaTZmsJr+UrHVOGV7scf/TlHNkq6PfESLWqcEO+V/k62qfUYKf4p2iZYUaBu/cVrokKYL7mbEA+c/21S2sTcPiwHqcFwVSyQD/mbD" ascii
      $s8 = "c/cKsWV2TZpeU9pU3c2kf277HoE/kY6EQNH87PH+JTYPdyXEi5SI/lSqcUs0sGuoxBrpWvfL2+fvCi4lO04VKT9+HNX8gvHVCKpvaBreOBpvaB4pdksP/y4mcwpvaBpv" ascii
      $s9 = "6vH/J4SUTI7PTMrkQyVDfVrUToVo74c+AU6Ek1fDfTbEs4cqaAEKJESDkLbEsb2D/Tp7cNfeA7V0fH7DilV2sxr8cWbpHrupJ1Hes8u7xl7N3QcDxUV2fVrP/6p03Kcv" ascii
      $s10 = "aBWIckuIbgW+HPHPHPHMaMwCD4w8H5SPDCXE7DY8gKw73w2UbtLbxO60WtLbxOYEiBsobCsIkBHpU2c7J2W8iJXE2gWMUNXEbMWIfTuP2gfNbCsP/ysE2gWMSnHEfxXl" ascii
      $s11 = "kiVETvVDkLbEdHXpk1H7f3HDkLbpkQbDTLH/sNfKkL2N3HEeThEkJcHUkhY+s4V/TB6vQyr8WvVEsr2D/1H/J9X8fTbocQbUQxH/JVXUCvbPJNrDUTpqs5HDkIX8UQb+" ascii
      $s12 = "SUlJSUlJSUlJbD0nc2hlbGxfZXhlYyc7')); ?><?php /* xorro@jabber.ru */$OOO000O00=$OOO000000{0}.$OOO000000{12}.$OOO000000{7}.$OOO0000" ascii
      $s13 = "fZV2f3Y+cdXITJE/QRV2f392kebpsLY2/0VKJYS8rlXL3MrDk02/f3YUCApKH7X/T87EAvY7717Ki2r7Q8EL38c7Q8VEk67IfZV2f3Y+bl7PkQbD/0V2f392kL2PH7r/" ascii
      $s14 = "D4wmgxs8UyLbx09BxKV2kQV2kQV2kQV2KAWLDCWKTWE03NrPBBEok392kL2PHcrLkb2v3ycksiVNQJEeiBHeJfY7J2SDdJ7Uk0VDfVrP/6p03KcDU02/bBHDkTVo3QVI" ascii
      $s15 = "Hp7PdE2UsiVKkEckQcEL3x2/2A2Ek67IfZV2f3Y+/ofo/QbD/0V2f392kL2PH7r/Hp7PdE2UsiVkfV7KHE2kH977CA7kfp2DTKpqs5HDkL2N3HEeThEkJcHDker8sNX2" ascii
      $s16 = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
      $s17 = "urn;?>hh]VRWJXQegwrL3wrL3wrLUvsIQjSP7BX8/NHVC0oUg8V2A/oUO0ZmW0WMGKpDgwreOBpvaBZMW0WMBKpDgwrLaBreOB4mcwpDOBrLaBreOxQeOBpvaBpDOBrm" ascii
      $s18 = "6PScsJ0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5Ky8nKSk7ZXZhbCgkT08wME8wME8wKTs='));ret" ascii
      $s19 = "aBpvaT9B==HEfxXla0w8JDXEBtLbxOY87JHLGfmNADYocyHpiIZ7fk6q7lYociW/sk60fxHEAywmgDYocyHpGfmNB5Y87JHLGfmCD4w8Q5HIKC6PsNX+A5SNDNrLaBrL" ascii
      $s20 = "BxQesrpDQ3p/fXQDkQV2kQV2kQV2kyVVss4mcQV2kQV2kQV2kQVpeT4py49B==khAwFv@Fr`uLrpS" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 9KB and
      8 of them
}

rule simple_php_backdoor92a3035e_8a1b_4d5d_9d12_b58bb84b75fe {
   meta:
      description = "php - file simple-php-backdoor92a3035e-8a1b-4d5d-9d12-b58bb84b75fe.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "1584efe90694a54a8b737a5d64cf69a11118b60b82dabb46786adb5702595fb1"
   strings:
      $s1 = "kTzBPMDBPTzAwKCRPMDAwTzBPMDAsMHgxN2MpLCdhM21MZS84SVdRNFpyZjl3YmNWcDI3RW82SFlYU3N1akNKTU5La1AweFRSMXlkaDVCQWx2RFUrcUdpRm5PZ3R6PSc" ascii /* base64 encoded string 'O0O00OO00($O000O0O00,0x17c),'a3mLe/8IWQ4Zrf9wbcVp27Eo6HYXSsujCJMNKkP0xTR1ydh5BAlvDU+qGiFnOgtz='' */
      $s2 = "PME8wMD0kT09PMDAwTzAwKCRPT08wTzBPMDAsJ3JiJyk7JE8wTzAwT08wMCgkTzAwME8wTzAwLDB4NTExKTskT08wME8wME8wPSRPT08wMDAwTzAoJE9PTzAwMDAwTyg" ascii /* base64 encoded string '0O00=$OOO000O00($OOO0O0O00,'rb');$O0O00OO00($O000O0O00,0x511);$OO00O00O0=$OOO0000O0($OOO00000O(' */
      $s3 = "vVDkLbEdKXEAF67JVYKkLbpkQceeqb+k3HDTWE03NrPBB6NfQHU3pbEd6r2i87EAYck7yS+k7YUH97L/VckCBcK7VcKkTE/cvVDkLbEdKrkHTV2f3HDkLbpkQbUQP7p3" ascii
      $s4 = "BrmCKpvaBreOBpvaBZmcwpvaBpvaBrLaTZmsJr+UrHVOGV7scf/TlHNkq6PfESLWqcEO+V/k62qfUYKf4p2iZYUaBu/cVrokKYL7mbEA+c/21S2sTcPiwHqcFwVSyQD/" ascii
      $s5 = "qYUk67N3JcNkqE7J9uKd2S+sP2oaib+UES+rl7Esku2/1H8UyuP/62PTZuorqV2CBVU/WpPAKcDi+6NQDS/TpH+kKXEAF67JVfKkTs+dKXEAF67JVYKd2SvDM9BTksP/" ascii
      $s6 = "y4mcIpegmb2ApElsQV2kQV2kQV2kQXeK0oVCKV2kQV2kQV2kQV2KA4VKnmNdk6+J5WmSfmk7v6Esk9M3xsIcB9MO5s8/lH+7DZPf5XVgvYEUBX82d6P/NY+c5XqWhS8J" ascii
      $s7 = "lHpGM9BTKYE2nm0D4QekQV2kQV2kQV2kQrVagWmQ4V/TB6vQyr/kibpkQbUQP2pai2/rBXeHou2xl67J9S8cWpEk67IfZ67sHHDdL2NQJEeiBHesfHU32r8sQY2kBV2J" ascii
      $s8 = "iu2kRSDdQbD/1EEDiY+7pbEsQbDeiV2f4b+co6vHQbUWBE7J4XkT62EsHXPd0VKJYS8rlXL3MrDk0p/f3Y+c6pPANY2/DV2fVY8c62Pg6rDQx6vffY2gqX+sQc+AdV2f" ascii
      $s9 = "8r+c6V0fYcUHR6NQVXedL2NfY7DkUVKsysE/TYvsLY2/0VKsBr7TW70fQbD/02/f3Y2U26vcr72TvE7s9SKkIYL3KVee+pIKGY+cIc0kYrk6BV2s4f2kL2NQJEeiBHeS" ascii
      $s10 = "0Y/TorosKV8d5VKJKX/kTYq3QVIf022SAY8/os+gQXEJx6+UVrUk6VPAJcUHxH8UEs2Adp0HM72Qh6ks8S8QLfETMrN3TpefVSEco2N/Mbqs1EEDiY+7ps+dKEeiy6+k" ascii
      $s11 = "mbDc/cKsWV2TZpeU9pU3c2kf277HoE/kY6EQNH87PH+JTYPdyXEi5SI/lSqcUs0sGuoxBrpWvfL2+fvCi4lO04VKT9+HNX8gvHVCKpvaBreOBpvaB4pdksP/y4mcwpva" ascii
      $s12 = "/2UcXQ+fdHmss4VknmP7NY8OCWNABSP2tWNy4Q8fdHmagWmCKoUQ/277/2UcXQ+fdHmss4py4QesrpDQ3p/fXQDkQV2kQV2kQV2kQXmss4mcNXEbT9BTk6+J5WmWOZq3" ascii
      $s13 = "E2UH17kfou2TQ7KHV27CBY/37r7/TE/cvVDkLbEdJ7v7AV2f3HDkLbpkQbUQP7p3E2UH17kfou2Tp2kH87kQEpk76r7Hp2Uf4HegqX+sQbUWBE7J4XkT62EsQcL306+U" ascii
      $s14 = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
      $s15 = "SUlJSUlJSUlJbD0nc3lzdGVtJzs=')); ?><?php /* xorro@jabber.ru */$OOO000O00=$OOO000000{0}.$OOO000000{12}.$OOO000000{7}.$OOO000000{5" ascii
      $s16 = "{11}.$OOO000000{12}.$OOO0000O0{7}.$OOO000000{5};?><?php eval($GLOBALS['OOO0000O0']('JElJSUlJSUlJSUlsST0nYmFzZTY0X2RlY29kZSc7JElJ" ascii
      $s17 = "00000{3}.$OOO000000{14}.$OOO000000{8}.$OOO000000{14}.$OOO000000{8};$OOO0O0O00=__FILE__;$OO00O0000=0x554;eval($OOO0000O0('JE8wMDB" ascii
      $s18 = "BpvaBpvaT9B==HEfxXla0wmedZV3pYEUBX82C2eJbW8QJ6+dKX+glW8QiWecZWmJxsIcB9MO5XEkNY8/kX8cJsli5SPSTWmDdwCD4Lbx09BTTHMJTSqfksmCKoUQ/277" ascii
      $s19 = "?>gSdgpKDo\\}SUr]DQegwrL3wrL3wrLUvsIQjSP7BX8/NHVC0oUg8V2A/oUO0ZmW0WMGKpDgwreOBpvaBZMW0WMBKpDgwrLaBreOB4mcwpDOBrLaBreOxQeOBpvaBpD" ascii
      $s20 = "LFlkG\\OQgGp" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 8KB and
      8 of them
}

rule Rootshell_v_1_0_encodedaae49d1f_c9b8_40c8_8d56_e6df87ec10b6 {
   meta:
      description = "php - file Rootshell.v.1.0-encodedaae49d1f-c9b8-40c8-8d56-e6df87ec10b6.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "6d042b6393669bb4d98213091cabe554ab192a6c916e86c04d06cc2a4ca92c00"
   strings:
      $s1 = "    |     Root Shell v1.0 - leetc0des.blogspot.com     |" fullword ascii
      $s2 = " goto vqgxJ; jTS05: goto HDDLU; goto N3Hzs; FFiUP: goto dsjV1; goto NjtG4; gc9kA: if (file_exists($xBtXh)) { goto PMs2g; } goto " ascii
      $s3 = "1tK; goto cDI0F; x3GbY: @($XZ0dj = system($_POST[\"\\x63\\x6f\\x6d\\155\\141\\x6e\\144\"])); goto oRV1t; yb1KD: gCqcL: goto U_r3" ascii
      $s4 = "sm; GTm2L: Np4L0(); goto wT80G; jByUQ: } goto u_F_I; KvJrB: @($XZ0dj = (include $_POST[\"\\x69\\x6e\\x63\\x6c\"])); goto bbD14; " ascii
      $s5 = "164\\x65\\x72\\x22\\76\\12\\40\\x20\\x3c\\x63\\x65\\x6e\\164\\x65\\162\\x3e\\xa\\40\\x20\\74\\x70\\76\\xa\\40\\x20\"; goto twAcr" ascii
      $s6 = "\\x6f\\x64\\145\\40\\x4f\\116\\x3c\\x2f\\x62\\76\\x3c\\x2f\\x66\\157\\156\\164\\76\"; goto VuxBC; Ypxc6: nP4l0(); goto puMgc; Y1" ascii
      $s7 = "\\76\\12\\74\\142\\x3e\\x3c\\x75\\x3e\\74\\x63\\145\\x6e\\164\\x65\\x72\\76\"; goto hhwkw; N3Hzs: Gohcp: goto VSRMo; puMgc: echo" ascii
      $s8 = "\\x73\\x69\\172\\x65\\75\\x22\\x32\\42\\76\\122\\157\\x6f\\164\\x73\\x68\\x65\\154\\154\\40\\166\"; goto PeDOr; hhwkw: echo \"" ascii
      $s9 = "\\145\\x72\\x76\\x65\\162\\40\\150\\x61\\163\\40\\142\\145\\x65\\x6e\\40\\x69\\x6e\\x66\\x65\\x63\\x74\\x65\\144\\x20\\142\\x79" ascii
      $s10 = "3e\\x3c\\x2f\\160\\76\\12\\x20\\x20\\40\\x20\\x20\\x20\\x3c\\x2f\\146\\x6f\\162\\155\\x3e\\xa\\40\\40\\40\\x20\\40\\40\"; goto K" ascii
      $s11 = "tFKUx: echo \"\\x3c\\57\\x63\\x65\\x6e\\164\\145\\x72\\x3e\\74\\57\\165\\76\\74\\x2f\\x62\\x3e\\12\\74\\150\\162\\x20\\x63\\x6f" ascii
      $s12 = "; VSRMo: print \"\\x3c\\x66\\157\\x6e\\x74\\x20\\143\\157\\154\\x6f\\x72\\75\\x23\\106\\106\\60\\60\\x30\\60\\x3e\\x3c\\142\\x3e" ascii
      $s13 = "106\\74\\57\\x62\\x3e\\74\\57\\146\\x6f\\x6e\\x74\\76\"; goto jTS05; h8wXl: goto dsjV1; goto BfXoV; NjtG4: PMs2g: goto rwJut; Wf" ascii
      $s14 = " echo \"\\74\\160\\40\\x61\\154\\151\\x67\\156\\75\\143\\x65\\156\\x74\\x65\\162\\x3e\\106\\x69\\x6c\\145\\x20\\x6e\\157\\164\\4" ascii
      $s15 = "prMqQ; prMqQ: if (!file_exists($xBtXh)) { goto P842k; } goto FFiUP; PeDOr: echo \"{$eie5M}\"; goto OUZDM; cDI0F: c6qeH: goto Ypx" ascii
      $s16 = "73\\x70\\x3b\\x3c\\x2f\\x70\\76\\12\\x3c\\57\\146\\x6f\\162\\155\\76\\xa\"; goto Bu4kd; vqgxJ: echo \"\\74\\x21\\x2d\\55\\12\\x2" ascii
      $s17 = "x70\\76\"; goto ennGd; IW3G_: $xBtXh = $X42N9; goto A7myT; j6dEn: copy($KhTBN, \"{$xBtXh}\"); goto gc9kA; VMIsC: dsjV1: goto WfS" ascii
      $s18 = "46\\x75\\154\\x3c\\57\\160\\76\"; goto h8wXl; U_r3X: echo \"\\x3c\\146\\x6f\\156\\x74\\x20\\146\\141\\x63\\145\\x3d\\x22\\x56\\1" ascii
      $s19 = "2f\\160\\76\"; goto VMIsC; RJAoU: echo \"\\x26\\156\\142\\x73\\x70\\x3b\\74\\57\\x70\\76\\74\\146\\x6f\\156\\x74\\x20\\146\\141" ascii
      $s20 = "$xBtXh = $DkYq3 . \"{$xBtXh}\"; goto IKEz1; wT80G: iqxkk: goto jByUQ; zXpd0: $DkYq3 = \"\\143\\x6f\\160\\x79\\137\\157\\146\\x5f" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      8 of them
}

rule jav_shellv1_1_maqlo66db1481_5db6_4308_be4c_d8e1f71ded9b {
   meta:
      description = "php - file jav-shellv1.1-maqlo66db1481-5db6-4308-be4c-d8e1f71ded9b.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "b66f9d00227742da3e02f9eb865550f2043ef64e341655d04d91c49ae8ee610e"
   strings:
      $s1 = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
      $s2 = "MTFJST0nY2xvc2VkaXInOyRJSUlJSUlJbDFsMTE9J2FycmF5X21lcmdlJzskSUlJSUlJSWwxbDFsPSdyZWFkZGlyJzskSUlJSUlJSWwxbGwxPSdvcGVuZGlyJzskSUlJ" ascii /* base64 encoded string '11II='closedir';$IIIIIIIl1l11='array_merge';$IIIIIIIl1l1l='readdir';$IIIIIIIl1ll1='opendir';$III' */
      $s3 = "SUkxPSdjdXJsX2luaXQnOyRJSUlJSUlJSWwxMWw9J3N1YnN0cic7JElJSUlJSUlJbDFsST0nc3RycG9zJzskSUlJSUlJSUlsbDFsPSdzcHJpbnRmJzskSUlJSUlJSUls" ascii /* base64 encoded string 'II1='curl_init';$IIIIIIIIl11l='substr';$IIIIIIIIl1lI='strpos';$IIIIIIIIll1l='sprintf';$IIIIIIIIl' */
      $s4 = "SWxsMT0nZ3ppbmZsYXRlJzskSUlJSUlJbElJbGxJPSdpc19maWxlJzskSUlJSUlJbElJbEkxPSdyZWFscGF0aCc7JElJSUlJSUkxMTFJMT0ncm1kaXInOyRJSUlJSUlJ" ascii /* base64 encoded string 'Ill1='gzinflate';$IIIIIIlIIllI='is_file';$IIIIIIlIIlI1='realpath';$IIIIIII111I1='rmdir';$IIIIIII' */
      $s5 = "b3Blbic7JElJSUlJSUkxSUkxST0nZGF0ZSc7JElJSUlJSUkxSUlJbD0nYmFzZTY0X2RlY29kZSc7JElJSUlJSUlsMTExMT0nYmFzZTY0X2VuY29kZSc7JElJSUlJSUls" ascii /* base64 encoded string 'open';$IIIIIII1II1I='date';$IIIIIII1IIIl='base64_decode';$IIIIIIIl1111='base64_encode';$IIIIIIIl' */
      $s6 = "JzskSUlJSUlJbElsbGxsPSdzeW1saW5rJzskSUlJSUlJbElsbGxJPSdteXNxbF9jbG9zZSc7JElJSUlJSWxJSWwxST0naHRtbHNwZWNpYWxjaGFycyc7JElJSUlJSWxJ" ascii /* base64 encoded string '';$IIIIIIlIllll='symlink';$IIIIIIlIlllI='mysql_close';$IIIIIIlIIl1I='htmlspecialchars';$IIIIIIlI' */
      $s7 = "bGxJPSdmaWxlcGVybXMnOyRJSUlJSUlJSWxsSUk9J3NoZWxsX2V4ZWMnOyRJSUlJSUlJSWxJMTE9J3Bhc3N0aHJ1JzskSUlJSUlJSUlsSWwxPSdleGVjJzskSUlJSUlJ" ascii /* base64 encoded string 'llI='fileperms';$IIIIIIIIllII='shell_exec';$IIIIIIIIlI11='passthru';$IIIIIIIIlIl1='exec';$IIIIII' */
      $s8 = "SUlJSWwxbElsPSdpbl9hcnJheSc7JElJSUlJSUlsMUkxMT0nc29ydCc7JElJSUlJSUlsMUlsST0nZmNsb3NlJzskSUlJSUlJSWwxSUkxPSdmd3JpdGUnOyRJSUlJSUlJ" ascii /* base64 encoded string 'IIIIl1lIl='in_array';$IIIIIIIl1I11='sort';$IIIIIIIl1IlI='fclose';$IIIIIIIl1II1='fwrite';$IIIIIII' */
      $s9 = "SWwxMT0nZmlsZXNpemUnOyRJSUlJSUlJSUlsMWw9J2Jhc2VuYW1lJzskSUlJSUlJSUlJbGwxPSdvYl9jbGVhbic7JElJSUlJSUlJSWxsST0naGVhZGVyJzskSUlJSUlJ" ascii /* base64 encoded string 'Il11='filesize';$IIIIIIIIIl1l='basename';$IIIIIIIIIll1='ob_clean';$IIIIIIIIIllI='header';$IIIIII' */
      $s10 = "SUlJSUkxSTFJbD0nbXlzcWxfcXVlcnknOyRJSUlJSUlJMUlsMTE9J215c3FsX2Nvbm5lY3QnOyRJSUlJSUlJMUlsMWw9J2d6d3JpdGUnOyRJSUlJSUlJMUlsbGw9J2d6" ascii /* base64 encoded string 'IIIII1I1Il='mysql_query';$IIIIIII1Il11='mysql_connect';$IIIIIII1Il1l='gzwrite';$IIIIIII1Illl='gz' */
      $s11 = "bDFJSWw9J2ZvcGVuJzskSUlJSUlJSWxsMTFJPSdpc19kaXInOyRJSUlJSUlJbGwxbDE9J2Rpcm5hbWUnOyRJSUlJSUlJbGwxbGw9J3VubGluayc7JElJSUlJSUlsbGxJ" ascii /* base64 encoded string 'l1IIl='fopen';$IIIIIIIll11I='is_dir';$IIIIIIIll1l1='dirname';$IIIIIIIll1ll='unlink';$IIIIIIIlllI' */
      $s12 = "dGFydCc7JElJSUlJSUlJSTExST0naXNfcmVhZGFibGUnOyRJSUlJSUlJSUkxbGw9J2lzX3dyaXRhYmxlJzskSUlJSUlJSUlJMUlJPSdyZWFkZmlsZSc7JElJSUlJSUlJ" ascii /* base64 encoded string 'tart';$IIIIIIIII11I='is_readable';$IIIIIIIII1ll='is_writable';$IIIIIIIII1II='readfile';$IIIIIIII' */
      $s13 = "SWxsSUlsST0nZmdldHMnOyRJSUlJSUlsbElJSWw9J2ZpbGVvd25lcic7JElJSUlJSWxJMTExMT0nZXJlZ2knOyRJSUlJSUlsSTFsMWw9J2hpZ2hsaWdodF9maWxlJzsk" ascii /* base64 encoded string 'IllIIlI='fgets';$IIIIIIllIIIl='fileowner';$IIIIIIlI1111='eregi';$IIIIIIlI1l1l='highlight_file';$' */
      $s14 = "aXInOyRJSUlJSUlJbElsSWw9J3N0cmlwc2xhc2hlcyc7JElJSUlJSUlsSWxJST0nYXJyYXlfbWFwJzskSUlJSUlJSWxJSTExPSdpc19hcnJheSc7JElJSUlJSUlsSUkx" ascii /* base64 encoded string 'ir';$IIIIIIIlIlIl='stripslashes';$IIIIIIIlIlII='array_map';$IIIIIIIlII11='is_array';$IIIIIIIlII1' */
      $s15 = "MT0nY29weSc7JElJSUlJSUlsbEkxbD0ncG9zaXhfZ2V0cHd1aWQnOyRJSUlJSUlJbGxJbDE9J2dldG15Z2lkJzskSUlJSUlJSWxsSWxJPSdnZXRteXVpZCc7JElJSUlJ" ascii /* base64 encoded string '1='copy';$IIIIIIIllI1l='posix_getpwuid';$IIIIIIIllIl1='getmygid';$IIIIIIIllIlI='getmyuid';$IIIII' */
      $s16 = "Ql3h6EUkwVsJsoc5o+ckHP/NH7gqSmSCsP/ysE2gQDJJYP/lWVe0wCD4mbKOZ+H5SPDtLbxQmpAMSNGOSq3JXNi9bNxC78g5XIrCYEiTWIs5SPyCYPk16V3KYETJX8/h" ascii
      $s17 = "bGw9J2ZpbGVtdGltZSc7JElJSUlJSWwxMWxJMT0nZmlsZXR5cGUnOyRJSUlJSUlsMTFJbGw9J2FycmF5X2RpZmYnOyRJSUlJSUlsMTFJSTE9J3JlbmFtZSc7JElJSUlJ" ascii /* base64 encoded string 'll='filemtime';$IIIIIIl11lI1='filetype';$IIIIIIl11Ill='array_diff';$IIIIIIl11II1='rename';$IIIII' */
      $s18 = "SUlJSUlJbEkxbDFJPSdzaG93X3NvdXJjZSc7JElJSUlJSWxJMWxsMT0naHRtbGVudGl0aWVzJzskSUlJSUlJbEkxSWxsPSdmaWxlJzskSUlJSUlJbElsMTFsPSd0cmlt" ascii /* base64 encoded string 'IIIIIIlI1l1I='show_source';$IIIIIIlI1ll1='htmlentities';$IIIIIIlI1Ill='file';$IIIIIIlIl11l='trim' */
      $s19 = "MWwxPSdhcnJheV9maWx0ZXInOyRJSUlJSUlJSTExbEk9J2V4cGxvZGUnOyRJSUlJSUlJSTFsMTE9J2FycmF5X3B1c2gnOyRJSUlJSUlJSTFsbDE9J3ByZWdfbWF0Y2hf" ascii /* base64 encoded string '1l1='array_filter';$IIIIIIII11lI='explode';$IIIIIIII1l11='array_push';$IIIIIIII1ll1='preg_match_' */
      $s20 = "SUlJbEkxPSdpbXBsb2RlJzskSUlJSUlJSUlJbElsPSdwcmVnX21hdGNoJzskSUlJSUlJSUlJSWxJPSdpbmlfc2V0JzskSUlJSUlJSUlJSUkxPSdjbGVhcnN0YXRjYWNo" ascii /* base64 encoded string 'IIIlI1='implode';$IIIIIIIIIlIl='preg_match';$IIIIIIIIIIlI='ini_set';$IIIIIIIIIII1='clearstatcach' */
   condition:
      uint16(0) == 0x3f3c and filesize < 1000KB and
      8 of them
}

rule kuda_encoded0483f3ec_17b5_4501_b187_aec42c81bb0b {
   meta:
      description = "php - file kuda-encoded0483f3ec-17b5-4501-b187-aec42c81bb0b.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "9922c802b98d00f0814e130baac918778cc8f9bdd0d313a50bbaaa799929efb4"
   strings:
      $s1 = "    |           Kuda - leetc0des.blogspot.com          |" fullword ascii
      $s2 = "x72\\163\", 0); goto btg0R; DzY7Q: error_reporting(0); goto N1clF; mk1vZ: eval(base64_decode($Vzk9B));" fullword ascii
      $s3 = " goto HMTpn; btg0R: $Z19xB = \"\\67\\x33\\x33\\146\\143\\66\\65\\x39\\x31\\x31\\x61\\x37\\62\\61\\65\\x34\\66\\x63\\64\\x36\\x34" ascii
      $s4 = "f\\x72\\137\\154\\x6f\\x67\", NULL); goto bB1gB; BVxid: set_time_limit(0); goto RA9UQ; RQ17E: error_reporting(0); goto BVxid; qC" ascii
      $s5 = "val(gzinflate(str_rot13(base64_decode($xyLT0)))); goto UGfHB; xCSxC: @ini_set(\"\\144\\x69\\163\\160\\154\\141\\x79\\137\\x65\\1" ascii
      $s6 = "145\\x63\\165\\x74\\151\\x6f\\x6e\\137\\x74\\151\\155\\145\", 0); goto W6lUm; RA9UQ: @byp79(0); goto RS5x2; Eyl0T: @ini_set(\"" ascii
      $s7 = "t(\"\\x6f\\x75\\164\\x70\\x75\\164\\x5f\\x62\\x75\\x66\\x66\\145\\x72\\x69\\156\\147\", 0); goto xCSxC; lEeXh: @ini_set(\"\\155" ascii
      $s8 = "4\\x77\\x55\\126\\116\\x42\\x6a\\67\\117\\x5a\\124\\x54\\106\\117\\125\\162\\104\\x52\\143\\x7a\\x2f\\x72\\x4c\\x77\\75\\x3d\"; " ascii
      $s9 = " @ini_set(\"\\154\\x6f\\x67\\x5f\\x65\\162\\162\\157\\162\\163\", 0); goto lEeXh; ZW2EX: $xyLT0 = \"\\127\\163\\151\\x37\\104\\1" ascii
      $s10 = " goto HMTpn; btg0R: $Z19xB = \"\\67\\x33\\x33\\146\\143\\66\\65\\x39\\x31\\x31\\x61\\x37\\62\\61\\65\\x34\\66\\x63\\64\\x36\\x34" ascii
      $s11 = "x34\\x61\\67\\70\\x31\"; goto ZW2EX; UGfHB: $Vzk9B = \"\\x4a\\110\\132\\160\\143\\62\\154\\60\\131\\171\\101\\71\\x49\\x43\\122" ascii
      $s12 = "o mk1vZ; HMTpn: session_start(); goto RQ17E; N1clF: @set_time_limit(0); goto qC7Po; RS5x2: @clearstatcache(); goto Eyl0T; bB1gB:" ascii
      $s13 = "\\123\\x57\\x79\\112\\123\\122\\126\\x46\\x56\\122\\x56\\116\\125\\x58\\61\\x56\\x53\\x53\\x53\\x4a\\144\\117\\167\\157\\x67\\x4" ascii
      $s14 = "\\144\\x58\\x4e\\x6c\\x63\\x69\\x77\\153\\x61\\62\\x46\\60\\131\\130\\116\\x68\\x62\\155\\x52\\x70\\x4b\\x54\\x73\\x67\\x66\\121" ascii
      $s15 = "\\x4b\\x41\\154\\x39\\x69\\x33\\104\\x7a\\152\\64\\x57\\112\\112\\x36\\x73\\130\\x30\\161\\x68\\x38\\154\\x52\\x6c\\x7a\\166\\x6" ascii
      $s16 = "\\x47\\x4d\\147\\x50\\x54\\60\\x67\\111\\151\\x49\\x70\\111\\x48\\x73\\x4b\\x49\\x43\\101\\153\\144\\155\\x6c\\172\\141\\130\\x5" ascii
      $s17 = "\\62\\164\\x70\\132\\x53\\x67\\x69\\144\\x6d\\154\\x7a\\x61\\x58\\122\\66\\111\\x69\\167\\x6b\\x64\\155\\154\\172\\141\\130\\122" ascii
      $s18 = "\\x4f\\x4d\\x6d\\x56\\x62\\170\\65\\143\\115\\x69\\163\\147\\x39\\x50\\x38\\x50\\x7a\\155\\153\\x38\\x63\\160\\157\\x34\\x45\\x7" ascii
      $s19 = "\\x4a\\x43\\x64\\x57\\143\\66\\111\\103\\122\\x30\\131\\x58\\x4a\\156\\132\\130\\121\\147\\x59\\156\\153\\x67\\112\\110\\x5a\\16" ascii
      $s20 = "\\101\\147\\111\\x43\\x41\\x39\\x49\\103\\122\\x66\\x55\\60\\x56\\x53\\x56\\153\\x56\\x53\\x57\\171\\x4a\\111\\x56\\106\\x52\\12" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 10KB and
      8 of them
}

rule webshell74e7adc8_7040_4806_bd94_088c3244c413 {
   meta:
      description = "php - file webshell74e7adc8-7040-4806-bd94-088c3244c413.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "9eb09598fb6da109d4c8001dacf2bdf2bd8572db0b8e60c326499ec7a7b7a135"
   strings:
      $s1 = " * https://www.whitewinterwolf.com/tags/php-webshell/" fullword ascii
      $s2 = "<input type=\"submit\" value=\"Execute\" style=\"text-align: right;\">" fullword ascii
      $s3 = "$p = popen('exec 2>&1; ' . $cmd, 'r');" fullword ascii
      $s4 = "$fetch_host = empty($_POST['fetch_host']) ? $_SERVER['REMOTE_ADDR'] : $_POST['fetch_host'];" fullword ascii
      $s5 = " * Use the 'passhash.sh' script to generate the hash." fullword ascii
      $s6 = " * Optional password settings." fullword ascii
      $s7 = "$ret = \"${err} Failed to open URL <i>${host}:${port}${src}</i><br />\";" fullword ascii
      $s8 = "$ret .= \"${err} Failed to connect to <i>${host}:${port}</i><br />\";" fullword ascii
      $s9 = "if (ini_get('file_uploads') && ! empty($_FILES['upload']))" fullword ascii
      $s10 = "$cmd = empty($_POST['cmd']) ? '' : $_POST['cmd'];" fullword ascii
      $s11 = " * along with this program.  If not, see <http://www.gnu.org/licenses/>." fullword ascii
      $s12 = "$p = popen('cmd /C \"' . $cmd . '\" 2>&1', 'r');" fullword ascii
      $s13 = " * This file is part of wwolf-php-webshell." fullword ascii
      $s14 = "$host = str_replace('https://', 'tls://', $host);" fullword ascii
      $s15 = "$host = 'http://' . $host;" fullword ascii
      $s16 = "$_FILES = &$HTTP_POST_FILES;" fullword ascii
      $s17 = "global $HTTP_POST_FILES, $HTTP_POST_VARS, $HTTP_SERVER_VARS;" fullword ascii
      $s18 = "function fetch_sock($host, $port, $src, $dst)" fullword ascii
      $s19 = "<input type=\"password\" size=\"15\" name=\"pass\">" fullword ascii
      $s20 = "$rh = fopen(\"${host}:${port}${src}\", 'rb');" fullword ascii
   condition:
      uint16(0) == 0x3c23 and filesize < 20KB and
      8 of them
}

rule SmallWebShellbyZaCo_encoded42500d8c_19fb_461d_a4d7_5ba374974d5f {
   meta:
      description = "php - file SmallWebShellbyZaCo-encoded42500d8c-19fb-461d-a4d7-5ba374974d5f.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "fbaf0627275b44d8a96c23c618e4b246867ba31a3997eef8f49afae8b183de7d"
   strings:
      $s1 = "    |     Small Web Shell - leetc0des.blogspot.com     |" fullword ascii
      $s2 = "\\167\\x6f\\162\\153\\x5f\\x64\\x69\\x72\\x27\\40\\164\\x79\\160\\145\\x3d\\150\\x69\\144\\144\\x65\\x6e\\x20\\x76\\141\\x6c\\x7" ascii
      $s3 = "\\154\\165\\145\\75\\47\"; goto ovv37; I8UJA: echo $JYnqh; goto T0vES; jtGe4: echo \"\\x27\\76\\15\\xa\\74\\151\\x6e\\160\\165" ascii
      $s4 = "4\\165\\145\\75\\47\"; goto HlOBy; FwtLK: echo \"\\x27\\x3e\\x3c\\57\\164\\x64\\x3e\\x3c\\x2f\\x74\\162\\x3e\\xd\\12\\74\\x74\\x" ascii
      $s5 = "F1L0h; ovv37: echo $lxhiN; goto zU4GJ; Xow7W: echo $Nu63P; goto FwtLK; KQiog: echo \"\\x27\\x20\\x73\\151\\x7a\\x65\\75\\61\\x32" ascii
      $s6 = " goto qMSHo; tO7zU: echo \"\\x27\\76\\x3c\\x2f\\x74\\144\\x3e\\74\\164\\144\\x3e\\x44\\x42\\x20\\x3a\\74\\x69\\156\\160\\x75\\x7" ascii
      $s7 = "x3d\\47\\144\\x62\\x27\\x20\\164\\x79\\160\\x65\\75\\164\\145\\x78\\x74\\x20\\x76\\141\\154\\x75\\145\\75\\x27\"; goto Xow7W; Hl" ascii
      $s8 = " goto qMSHo; tO7zU: echo \"\\x27\\76\\x3c\\x2f\\x74\\144\\x3e\\74\\164\\144\\x3e\\x44\\x42\\x20\\x3a\\74\\x69\\156\\160\\x75\\x7" ascii
      $s9 = " WTetC; VBrVn: echo \"\\47\\76\\74\\57\\164\\x64\\76\\x3c\\57\\164\\x72\\76\\xd\\12\\x3c\\164\\x72\\76\\x3c\\x74\\x64\\76\\117" ascii
      $s10 = "LITO0; WTetC: echo str_replace(\"\\47\", \"\\46\\43\\60\\63\\x39\\x3b\", $IKyqA); goto jtGe4; F1L0h: echo $IjmWW; goto tO7zU; kD" ascii
      $s11 = "166\\141\\154\\165\\x65\\x3d\\x27\"; goto wFv86; T0vES: echo \"\\x27\\76\\x3c\\57\\x74\\144\\x3e\\74\\x74\\x64\\76\\x50\\x61\\x7" ascii
      $s12 = "x30\\x3e\"; goto zpMWJ; qMSHo: echo \"\\74\\77\\xd\\xa\\40\\40\\x23\\43\\43\\x23\\x23\\x23\\x23\\x23\\43\\43\\x23\\43\\43\\43\\4" ascii
      $s13 = " wFv86: echo $Nu63P; goto VBrVn; LITO0: echo \"\\x27\\76\\74\\57\\x74\\144\\76\\74\\x74\\144\\76\\110\\x6f\\x73\\164\\x20\\x3a" ascii
      $s14 = "oto I8UJA; h327J: echo $lxhiN; goto KQiog; zpMWJ: echo htmlspecialchars($vkgAQ); goto kDFn2; zU4GJ: echo \"\\x27\\40\\x74\\171" ascii
      $s15 = "\\157\\163\\x69\\170\\137\\x67\\x65\\x74\\x67\\x72\\x67\\151\\144\\x28\\100\\146\\151\\x6c\\x65\\x67\\162\\x6f\\x75\\160\\50\\44" ascii
      $s16 = "\\x50\\117\\x53\\124\\x5b\\47\\144\\x62\\137\\144\\165\\155\\x70\\x27\\x5d\\x3a\\47\\47\\x3b\\15\\12\\x24\\164\\141\\142\\154\\x" ascii
      $s17 = "\\x6e\\x65\\x63\\x74\\40\\x65\\x72\\162\\x6f\\x72\\x27\\x29\\73\\xd\\12\\145\\154\\163\\145\\15\\xa\\x7b\\15\\xa\\x2f\\x2f\\x40" ascii
      $s18 = "\\145\\x20\\x69\\146\\x20\\x79\\157\\165\\x20\\x68\\x61\\166\\x65\\40\\160\\162\\x6f\\142\\154\\145\\155\\163\\x20\\x77\\x68\\15" ascii
      $s19 = "\\40\\x76\\141\\x6c\\x75\\x65\\x3d\\47\\147\\172\\151\\x70\\47\\40\\x63\\150\\145\\143\\x6b\\x65\\x64\\x3d\\x74\\162\\x75\\x65" ascii
      $s20 = "\\150\\x6f\\x28\\47\\x3c\\163\\x74\\x72\\x6f\\156\\147\\76\\x4c\\151\\x73\\x74\\151\\x6e\\x67\\40\\47\\56\\x24\\x65\\137\\x77\\1" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      8 of them
}

rule bypass403bc2cc0f9_5443_44d2_9261_153a3cd72e01 {
   meta:
      description = "php - file bypass403bc2cc0f9-5443-44d2-9261-153a3cd72e01.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "2e94593ca67d7710be39c1d2ef1d0636068ec5ec4ce38f3fce5dd1c5ed12f15e"
   strings:
      $s1 = "ST0nc3ltbGluayc7JElJSUlJSUlJSWxsMT0ndHJpbSc7JElJSUlJSUlJSWxJST0nY2hkaXInOyRJSUlJSUlJSUlJMUk9J3N5c3RlbSc7JElJSUlJSUlJSUlsMT0nZXhw" ascii /* base64 encoded string 'I='symlink';$IIIIIIIIIll1='trim';$IIIIIIIIIlII='chdir';$IIIIIIIIII1I='system';$IIIIIIIIIIl1='exp' */
      $s2 = "gvsmWtLbxO6+7hs87lwCD4w8cTsM3vsIkyHpDMs87GsmUJX8k0XNxC6+7hs87l9lWtw8QTHvGOSq3JXM3vsIkyHpDMY87TH+JD9MaBSICnWNGO6Pk0WIfDuEAkwVQPX+" ascii
      $s3 = "UvS8/NYEi09MaBSICnWM3NX8/vSvDMbo3BX82dSqciX82dSq3JXMWtw8H5X0bC6+gyXqWgW0sxYockWM3vYoTkwVW+WNGO6Pk0wNAvS8/hWIfDuEAkwVQPX+iDZoskYE" ascii
      $s4 = "bC6+gyXqWgW0sxYockWM3vYoTkwVWlWNGO6Pk0wNAvS8/hWIfDuEAkwVQPX+iDZoskYEsxsLxC6PgyHLyCs87GsmUvY8/KXqSFWIsxYockWL3BumaBSICCrpQBuLyC6+" ascii
      $s5 = "sTHIcx9MakrpaB9BD4mbKQmbKQmEJkYEsxsLxCQpeBrLyfmCKQmbKQmbkDHoJDZE/yYEsh9PfkX0ckSNyfmCKQmbKQmbkd6oQ0YEGFWLaC6o7DXvyfmCKQmbKQmbkB6E" ascii
      $s6 = "gmb2ApElsQV2kQV2kQV2kyrEB0oVC0ZlShQ8J5XE2hQlO0ZMcUS+7lZMS5SI7MX8kNo+JDXEB56PA5HlgNX+iPYEsUSP/DYEghZ03xSmSyQI7vHoWhQDTwpDUrbViDuI" ascii
      $s7 = "kQV2kQV2kQXL/yQUDxQlO0ZMcxX+UkZMS5QlGKsofkSMG0Zq3U6PAT6Ugxs8UyZ+J5SqcTXPS56+ghHPk0soQJs8k5XMiBYIa0ZmcUS+7lZMsoVeUL2liDuIb04py4Qe" ascii
      $s8 = "7vHoWhQlgBsEQyYEfjYIcdXmgduVgNX+iPYEsUSP/DYEghZ03xSmSyQI7vHoWhQUsWp2fpZ0cGsmST9BxKcDAwbK/r2Uy0V2kQV2kQV2kQXL/yQUDxQlO0ZMcxX+UkZM" ascii
      $s9 = "QlZvGOZ+H5SPDtQvy4YE6C4mcj2egp7/y06+ghHMss4V3nmMcxX+UkWLDCQ/gbpUf2ElsxX+UkQUDnmMcQV2kQV2kQV2kQrpeCwVaKY8gdHpy4b8U1H8kl4mcQV2kQV2" ascii
      $s10 = "/QQUDxQlg+6oW5sqsqZ+f5XPHTHlgNX+ihHEfDZ03xSmSyQDg2Ve7VZ0cGsmST9BxKcDAwbK/r2Uy0V2kQV2kQV2kQXL/QQUDxQlg+6oW5sqsqZ+kh6+AUH8256+ghXP" ascii
      $s11 = "SyQI7vHoWhQUsWp2fpZ0cGsmST9BxKcDAwbK/r2Uy0V2kQV2kQV2kQXL/QQUDxQlO0ZMcxX+UkZMS5QlGKsofkSMG0Zq3U6PAT6Ugxs8UyZqsxXEfvZ+f5XPHTHq7l6o" ascii
      $s12 = "7J6+CxQekQV2kQV2kQV2kQXm3JSlaKV2kQV2kQV2kQVEAQ4Va4uBxKSqclwVcIpegmb2ApElsQV2kQV2kQV2kQXLe0oVCM9MWyQekQV2kQV2kQV2kyVVKnmP7NY8OCQI" ascii
      $s13 = "3h6EUkwVQUS8A56EckSMWCYEbgW07BX8gJH87lWNG09+7NY8OCQvATX03Usm3Duo3kwVQPYEAkWM3h6EUkwVQPYEAkWM3vYoTkwVWUrmWtw8khSI7DW8iJXE2gWkgUS8" ascii
      $s14 = "GKsofkSMG0Zq3U6PAT6Ugxs8UyZqfTs825sqad6+ghHPk0Z03xSmSyQI7vHoWhQUsw2Kcb2K7p2liDuIb04py4QesrpDQ3p/fXQDkQV2kQV2kQVEBAVVss4mS5QlGKY8" ascii
      $s15 = "Qd6EBnW8glS8JJX0rFWLWnW8AksIckSMUvS8/NYEi09M3hXqQd6EBnW8f5X8gl9M3lH+WxrmBCrmBCrmKnWIs5SPbdSq3J6+khHvxCrI3G9lWC6+AJSqrgWK/BS8AkZo" ascii
      $s16 = "QP6Efk6Pg5YqdBXqfTs8k5XNTPYoJkHLyCs8gB9NWBrI3G9l3yHEHD9NeBSICnW8UJumUxHEk0YIbFrpaBSICnW8UJumUqYEcDYLxArL3BuLyCs+kKs8CFWLeBrm2nW8" ascii
      $s17 = "S5SI7MX8kNo+JDXEB5Sq7BS8glsmgNX+iPYEsUSP/DYEghZ03xSmSyQI7vHoWhQUsWp2fpZ0cGsmST9BxKcDAwbK/r2Uy0V2kQV2kQV2kQXL/QQUDxQlO0ZMcxX+UkZM" ascii
      $s18 = "S5QlGKsofkSMG0Zq3U6PAT6Ugxs8UyZ+Ui6EfNXq7hsmgNX+iPYEsUSP/DYEghZ03xSmSyQI7vHoWhQUsWp2fpZ0cGsmST9BxKcDAwbK/r2Uy0V2kQV2kQV2kQXL/yQU" ascii
      $s19 = "ShQI7vHoWhQlgBsEQyYEfjYIcdXmgoVeUL2lgNX+iPYEsUSP/DYEghZ03xSmSyQI7vHoWhQUsWp2fpZ0cGsmST9BxKcDAwbK/r2Uy0V2kQV2kQV2kQXL/yQUDxQlO0ZM" ascii
      $s20 = "cTX+GhS8JBQlBKsofkSMG07DJfbUrhsIJDQlKnmMcIpegmb2ApElsQV2kQV2kQV2kyr2K0oVC0ZlShQ8J5XE2hQlO0ZMcUS+7lZMS5SI7MX8kNo+JDXEB5s+Jd6qrlZ+" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      8 of them
}

rule safe0ver313ba731_25f0_44db_8477_032a89e27e44 {
   meta:
      description = "php - file safe0ver313ba731-25f0-44db-8477-032a89e27e44.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "0b17d2030491bc4822448a070a5c5506a38e2321f3ef83ba0b88656af1e08e61"
   strings:
      $s1 = "SUlJSUlsSTExMT0nc2hlbGxfZXhlYyc7JElJSUlJSUlsSTExST0naW5pX3Jlc3RvcmUnOyRJSUlJSUlJSTExMTE9J2FycmF5X21lcmdlJzskSUlJSUlJSUkxMTFJPSdy" ascii /* base64 encoded string 'IIIIIlI111='shell_exec';$IIIIIIIlI11I='ini_restore';$IIIIIIII1111='array_merge';$IIIIIIII111I='r' */
      $s2 = "ZXNldCc7JElJSUlJSUlJMTFsMT0nc29ydCc7JElJSUlJSUlJMTFsbD0ndXNvcnQnOyRJSUlJSUlJSTExbEk9J3N0cnRvbG93ZXInOyRJSUlJSUlJSTFsMWw9J2NvdW50" ascii /* base64 encoded string 'eset';$IIIIIIII11l1='sort';$IIIIIIII11ll='usort';$IIIIIIII11lI='strtolower';$IIIIIIII1l1l='count' */
      $s3 = "SUlJSUlJSUlJbDExPSdzdWJzdHInOyRJSUlJSUlJSUlsMWw9J3N0cnBvcyc7JElJSUlJSUlJSWxsbD0ndXJsZW5jb2RlJzskSUlJSUlJSUlJbGxJPSdpc19hcnJheSc7" ascii /* base64 encoded string 'IIIIIIIIIl11='substr';$IIIIIIIIIl1l='strpos';$IIIIIIIIIlll='urlencode';$IIIIIIIIIllI='is_array';' */
      $s4 = "JzskSUlJSUlJSUkxbElsPSdyZWFscGF0aCc7JElJSUlJSUlJMUlJbD0ndW5saW5rJzskSUlJSUlJSUkxSUlJPSdybWRpcic7JElJSUlJSUlJbDExMT0nY2xvc2VkaXIn" ascii /* base64 encoded string '';$IIIIIIII1lIl='realpath';$IIIIIIII1IIl='unlink';$IIIIIIII1III='rmdir';$IIIIIIIIl111='closedir'' */
      $s5 = "OyRJSUlJSUlJSWwxMWw9J3JlYWRkaXInOyRJSUlJSUlJSWwxbDE9J29wZW5kaXInOyRJSUlJSUlJSWwxbEk9J2lzX2Rpcic7JElJSUlJSUlJbEkxMT0naGVhZGVyJzsk" ascii /* base64 encoded string ';$IIIIIIIIl11l='readdir';$IIIIIIIIl1l1='opendir';$IIIIIIIIl1lI='is_dir';$IIIIIIIIlI11='header';$' */
      $s6 = "y4HEfxXlaMw8khSI7DWIfTuP2gomWArL3SWM3Duo3kw7BMs87Gs/BMW8iJXE2gomQhHosPYEAkomWCsP/ysE2gomWKV2kQV2kQVEAQr2KAomWtw8QlwNATX03Usm3Duo" ascii
      $s7 = "kQV2kyV2KArVghHosPYEAkQekQV2kQV2kQX8BAVViDuIbMZmQq4lWT9BTTHMaxQ8HTX82CwpDCHP/yS+2TmP7NY8OCWKf5sEAKW8i5sm3NSP7Js82Cs8JkW8iksl3PYE" ascii
      $s8 = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
      $s9 = "AkZMGhw8QlwMWnmP7yS+24HEfxXlaM2q7N6+7vS+HUX8AiW8flHE/DHEbFW/BMQekQV2kQV2kyV2KArVghHosPYEAkQekQV2kQV2kQX8BAVViDuIcSWNAMSNGM9BTk6+" ascii
      $s10 = "GMwKILT+k1W/35S0cy6oWOZ+gBs8k5XNGfmMaCWmaCWmaCWmaCWmaCWmaCw8gBs8k5XM3+6EAUHpDMSIrCZE/UumWtBGsJX8kv6EGC7ok0sEAJXE/y6oWOZ+gBs8k5XN" ascii
      $s11 = "kkXPKCc8gvuEeCjmWyWPfdHLUhHosPYEAkQPAJSqcNXEbgH8klQPAJSqcKYoWgQ8cTSMWTZMQSXMWhV2kQV2kQV2kyX8Ay4LrTZCTQV2kQV2kQVEAyV2KxWmQOW/kkXP" ascii
      $s12 = "D4WmaCWmaO60WtwIatw8QlwkfJHP2CpEgKHV3mu733SqrOSLGOHPglXV3dHocxX+bgWk3w2UbMwCD4WaKOSm3JX8k0XNDM6+7hs87lWNGOYEiBsobCsIkBHpDMs87Gsm" ascii
      $s13 = "3SWM3Duo3kw7BMs87Gs/BMW8iJXE2gomQPYEAkomWCsP/ysE2gomWKHPkyH7BMwkAhWNy4HEfxXlaMw8khSI7DWIciS82gomQvsEQdYocSWM3+6EAUHpUSWkfJsP7SWN" ascii
      $s14 = "6C4m3aYofjSP7JH8/MX82xWMcKYoW5Q8HTX82M4VaTmP7NY8OCWNADSNGOs8bCpKgo2K/bW8fy6ofvw7BMs8gBW8AkH0bCSPk0YIbCQekQV2kQV2kyV2kyr7BMwMWhV2" ascii
      $s15 = "kyHVagW8U1H8kl4mWKV2kQV2kQVEAQVpeAZ+iks+cTSMcQV2kQV2kQVEAyr2KMZLaqfvST9BTTHMaxQ8HTX82CwpDCHP/yS+2TmP7NY8OCWKf5sEAKW8i5sm3NSP7Js8" ascii
      $s16 = "JTH8ckXkBMW8iJXE2gomQy6ofDH8klomWCsP/ysE2gomWKV2kQV2kQVEAQVpeAomWto8GM9BTk6+J5WmQVHEiJXE2ComWKV2kQV2kQVEAQX8AQomWCs8OFw8QlwkAhWN" ascii
      $s17 = "AMSNGO60WtWNy4HEfxXlaMES9OY+AkXP7hWec5SqkJWe/KYpxComWKsofkSPHTX87jXP/dH7BMZkAhw8QlwKc5SqkJWe/KYpxComWKsofkSPHTX87SWMiSXNAMSNGM9B" ascii
      $s18 = "2T4bxKSP7vWLDC6+gBuVCKsofkSPHTX82yWMcKYoW5QI7vHoQPYEAko+iJXE2M4py4HEfxXlaM7o3yX+/KHEbComWKsofkSPHTX87jXP/dH7BMWIc5W/BMQI7vHoQPYE" ascii
      $s19 = "AkomWnWLAMSNiSXMWnmPkPWmCKSP7v4V3nmP7NY8OCWKQJS+/lYoky6V3HBnA1X87hH8KComWKsofkSPHTX87SWM3DXl3SWMcKYoW5QI7vHoQPYEAko+iJXE7SWMiSXN" ascii
      $s20 = "i0wMWnmPkPWmCCb8kvo+7GHEfUs8/MX82xWMcKYoW5Q8HTX82M4VaTmP7NY8OCWNApsIQ5XPStELAvsIQ5XPStWNy4YE6C48HUXPfDYEgho+7GYofDSlC0Yofjso3yX+" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      8 of them
}

rule Safe_ModeBypassPHP4_4_2andPHP5_1_2_encoded44637130_bc07_4c21_8489_a8cfd78b65ca {
   meta:
      description = "php - file Safe_ModeBypassPHP4.4.2andPHP5.1.2-encoded44637130-bc07-4c21-8489-a8cfd78b65ca.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "655e91b4b3ad5cc25859d028aad3db04e824bb1d827b08e078f706f8c1318853"
   strings:
      $s1 = "    |    Safe Mode ByPass - leetc0des.blogspot.com     |" fullword ascii
      $s2 = " goto tM4vt; h1082: echo \"\\x3c\\102\\x3e\\55\\55\\55\\x20\\123\\164\\x61\\162\\x74\\x20\\x46\\151\\154\\145\\x20\" . htmlspeci" ascii
      $s3 = "5\\x64\\x69\\x72\"); goto jjZVX; bGc1D: $heQKc = $ssqQB - $Kr_vV; goto j1tQQ; y1h_J: echo \"\\117\\x70\\145\\156\\x20\\142\\x61" ascii
      $s4 = "o y1h_J; tutT2: goto DqsKN; goto DHe4H; mKNQO: if ($Kr_vV) { goto B5TMY; } goto C0nRy; Xbvnx: $ahqXr = tempnam($OPNxI, \"\\x63" ascii
      $s5 = "\\145\\76\\x3c\\57\\150\\x65\\x61\\144\\x3e\"; goto Df6dY; vpM84: if (empty($_GET[\"\\146\\151\\x6c\\145\"])) { goto z_uYA; } go" ascii
      $s6 = "\"); goto XXFdE; cdyPw: $yd7T3 = fopen($ahqXr, \"\\x72\"); goto Sidb_; h0gWF: $SdeOM = @ini_get(\"\\157\\x70\\x65\\x6e\\137\\142" ascii
      $s7 = "3\\105\\x4e\\124\\x45\\122\\76\\74\\x2f\\x42\\x3e\"); goto cL3kG; vCeOu: if (@ini_get(\"\\163\\141\\x66\\x65\\x5f\\x6d\\157\\x64" ascii
      $s8 = "; Myras: wJPzJ: goto cbRiE; tAU3R: if ('' == ($H5K1A = @ini_get(\"\\144\\x69\\163\\x61\\x62\\x6c\\x65\\137\\x66\\165\\x6e\\x63" ascii
      $s9 = "to RB5wQ; EPlnb: if (empty($_POST[\"\\146\\151\\x6c\\145\"])) { goto c0yxY; } goto Qf033; nXOWu: DJCm8: goto nD7JA; Df6dY: $Zvo_" ascii
      $s10 = "_GET[\"\\146\\x69\\154\\x65\"]; goto heo4a; Qf033: $aeyv_ = $_POST[\"\\146\\151\\x6c\\145\"]; goto bKkxU; heo4a: goto h9V4d; got" ascii
      $s11 = "(@ini_get(\"\\x73\\x61\\146\\145\\x5f\\x6d\\x6f\\144\\145\")) == \"\\157\\156\") { goto DJCm8; } goto wlbHP; WKntC: $ssqQB = 0; " ascii
      $s12 = "e\\117\\x4e\\40\\x28\\163\\145\\143\\x75\\162\\x65\\x29\\74\\57\\x66\\157\\156\\x74\\76\"; goto AGuy2; Sidb_: $sHJQk = fread($yd" ascii
      $s13 = " eval(base64_decode($Zvo_E)); goto Td5sA; URM7C: $k3Kkm = \"\\74\\x66\\157\\x6e\\164\\x20\\x63\\157\\154\\157\\162\\x3d\\x22\\x7" ascii
      $s14 = "\\40\\x3c\\142\\76\"; goto tAU3R; j1tQQ: $hjlHy = @round(100 / ($ssqQB / $Kr_vV), 2); goto S_0pk; Jdq7e: c0yxY: goto ogOoN; vksL" ascii
      $s15 = "\\x2f\\160\\x3e\\xa\\x9\\74\\57\\x66\\x6f\\162\\155\\x3e\\12\\xa\\12\"; goto xz77m; ewERa: aUOi1: goto Xbvnx; f3Izy: echo \"\\x3" ascii
      $s16 = "76\\xa\\73\\x5d\\74\\x2f\\102\\76\\74\\57\\106\\117\\x4e\\x54\\x3e\"); goto E1ZDb; DHe4H: Kc2Au: goto cdyPw; cbRiE: $dpPTI = tru" ascii
      $s17 = "DrPKz; E1ZDb: DqsKN:" fullword ascii
      $s18 = "r)); goto Rovxb; cECjj: echo \"\\123\\x61\\146\\145\\x2d\\x6d\\157\\144\\145\\72\\40{$k3Kkm}\"; goto h0gWF; wlbHP: $GlJ0C = fals" ascii
      $s19 = "x64\\x69\\162\\72\\40{$mtnRB}\"; goto veAJi; XXFdE: if (copy(\"\\143\\x6f\\x6d\\160\\162\\x65\\x73\\163\\x2e\\x7a\\x6c\\151\\x62" ascii
      $s20 = " goto tM4vt; h1082: echo \"\\x3c\\102\\x3e\\55\\55\\55\\x20\\123\\164\\x61\\162\\x74\\x20\\x46\\151\\154\\145\\x20\" . htmlspeci" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 60KB and
      8 of them
}

rule SimAttacker_Version1_0_0_encodedd4ef85b2_6284_4253_91d1_78a7df87a860 {
   meta:
      description = "php - file SimAttacker-Version1.0.0-encodedd4ef85b2-6284-4253-91d1-78a7df87a860.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "cad1a17a4adb2b0ef4550d2b853531483e7ab6658bb3459ba7da7e4d1a304704"
   strings:
      $s1 = "    |     Sim Attacker v1 - leetc0des.blogspot.com     |" fullword ascii
      $s2 = " echo \"\\x3c\\77\\12\\x2f\\x2f\\144\\157\\167\\x6e\\x6c\\x6f\\141\\144\\x20\\x46\\151\\154\\145\\x73\\40\\40\\x43\\157\\144\\14" ascii
      $s3 = " echo \"\\x3c\\77\\12\\x2f\\x2f\\144\\157\\167\\x6e\\x6c\\x6f\\141\\144\\x20\\x46\\151\\154\\145\\x73\\40\\40\\x43\\157\\144\\14" ascii
      $s4 = "\\52\\x2a\\52\\x2a\\52\\x2a\\x2a\\x2a\\x2a\\x2a\\x2a\\52\\52\\52\\x2a\\x2a\\x2a\\x2a\\52\\xa\\12\\x9\\x9\\11\\x2f\\57\\103\\157" ascii
      $s5 = "\\x3c\\x73\\x70\\x61\\x6e\\x20\\163\\x74\\x79\\154\\x65\\75\\x27\\x74\\145\\x78\\164\\55\\144\\x65\\143\\157\\162\\x61\\164\\151" ascii
      $s6 = "\\x22\\x3c\\142\\162\\x3e\\x49\\x50\\40\\72\\x22\\56\\x20\\xa\\50\\44\\x5f\\x53\\105\\x52\\126\\105\\122\\x5b\\x27\\122\\x45\\11" ascii
      $s7 = "\\x46\\x72\\151\\145\\x6e\\144\\x73\\x20\\135\\x20\\74\\x62\\162\\x3e\\12\\52\\x2a\\52\\x2a\\x2a\\52\\x2a\\x2a\\x2a\\x2a\\x2a\\x" ascii
      $s8 = "\\52\\x2a\\x2a\\x2a\\52\\x2a\\x2a\\x2a\\x2a\\x2a\\52\\x2a\\x2a\\x2a\\x2a\\52\\52\\x2a\\52\\x2a\\x2a\\52\\52\\x2a\\x2a\\52\\x2a" ascii
      $s9 = "\\60\\x30\\60\\x27\\x20\\x73\\151\\172\\145\\75\\47\\62\\47\\76\\x3c\\142\\x3e\\104\\x65\\154\\145\\x74\\145\\74\\57\\x62\\x3e" ascii
      $s10 = "\\156\\164\\x65\\x6e\\164\\55\\104\\151\\163\\x70\\x6f\\x73\\151\\164\\151\\157\\x6e\\x3a\\x20\\141\\x74\\164\\x61\\143\\150\\x6" ascii
      $s11 = "\\76\\12\\x22\\x3b\\12\\xa\\x65\\143\\150\\157\\x20\\42\\x3c\\x66\\x6f\\156\\x74\\x20\\x63\\x6f\\x6c\\157\\162\\x3d\\x27\\43\\63" ascii
      $s12 = "\\153\\40\\x53\\x68\\145\\154\\x6c\\40\\x2c\\40\\142\\x79\\x70\\141\\x73\\x73\\x20\\x46\\151\\x72\\145\\167\\141\\x6c\\154\\x73" ascii
      $s13 = "\\66\\x36\\66\\x36\\x22\\x20\\x73\\151\\x7a\\x65\\x3d\\42\\x31\\42\\x20\\146\\x61\\x63\\145\\x3d\\42\\124\\141\\x68\\x6f\\155\\1" ascii
      $s14 = "\\151\\x7a\\x65\\75\\47\\61\\47\\76\\x64\\x69\\162\\x3c\\57\\146\\157\\x6e\\x74\\76\\42\\73\\12\\x9\\x9\\x7d\\12\\11\\11\\145\\1" ascii
      $s15 = "\\56\\143\\157\\x6d\\x22\\x3b\\12\\x9\\11\\44\\163\\165\\x62\\x6a\\145\\143\\x74\\x3d\\40\\155\\144\\x35\\50\\x22\\x24\\x66\\162" ascii
      $s16 = "\\157\\x20\\x22\\74\\141\\x20\\x68\\x72\\145\\146\\75\\x27\\77\\x69\\144\\75\\146\\x6d\\46\\144\\x69\\162\\75\\44\\144\\151\\162" ascii
      $s17 = "\\x20\\x20\\x20\\x20\\x3c\\151\\156\\x70\\x75\\164\\x20\\164\\171\\x70\\145\\x3d\\x27\\x68\\151\\x64\\144\\x65\\156\\47\\x20\\x6" ascii
      $s18 = "\\x7d\\12\\x20\\40\\145\\154\\163\\x65\\x7b\\12\\145\\x63\\150\\x6f\\40\\42\\x3c\\163\\143\\x72\\151\\160\\164\\x20\\154\\141\\x" ascii
      $s19 = "\\40\\40\\40\\40\\40\\x20\\x20\\40\\74\\142\\162\\76\\42\\73\\xa\\xa\\11\\x9\\x9\\x65\\143\\x68\\x6f\\40\\x22\\12\\xa\\x3c\\144" ascii
      $s20 = "\\154\\x65\\75\\x22\\x74\\145\\170\\164\\55\\144\\145\\x63\\x6f\\x72\\141\\164\\x69\\x6f\\x6e\\72\\x20\\x6e\\x6f\\x6e\\145\\x22" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      8 of them
}

rule Simple_PHP_backdoor_by_DK_encodedfbf56f6b_bb5f_4cfc_9408_799ea6153b62 {
   meta:
      description = "php - file Simple_PHP_backdoor_by_DK-encodedfbf56f6b-bb5f-4cfc-9408-799ea6153b62.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "47b47dd3aef1609ce3b67beb9311ce4388dd69fb2b86696d8b6dbdaf2579d151"
   strings:
      $s1 = "    |   Simple PHP Backdoor - leetc0des.blogspot.com   |" fullword ascii
      $s2 = "76\\12\\12\"; goto Z237s; VMo3U: system($dW62L); goto fOQ6I; DpnYB: die; goto PWUdh; RdzWe: echo \"\\12\\125\\163\\x61\\x67\\x65" ascii
      $s3 = " goto nhPFr; PWUdh: Wca3D: goto mfc5z; NlHXL: echo \"\\x3c\\x70\\x72\\145\\x3e\"; goto k85_a; SpxzD: eval(base64_decode($ik04L))" ascii
      $s4 = "\\x64\"]; goto VMo3U; nhPFr: echo \"\\xa\\x3c\\x21\\x2d\\x2d\\40\\123\\x69\\155\\x70\\x6c\\145\\40\\120\\110\\x50\\40\\x62\\x61" ascii
      $s5 = "44\\x47\\x4d\\x70\\x4f\\167\\75\\75\"; goto SpxzD; fOQ6I: echo \"\\74\\x2f\\160\\162\\x65\\76\"; goto DpnYB; k85_a: $dW62L = $_R" ascii
      $s6 = "\\71\\104\\x51\\x70\\154\\x62\\110\\x4e\\154\\x49\\x48\\163\\147\\112\\110\\132\\x70\\x63\\62\\x6c\\x30\\131\\171\\x73\\162\\117" ascii
      $s7 = "\\x77\\x30\\x4b\\111\\x43\\101\\x6b\\131\\155\\x39\\x6b\\145\\123\\x41\\147\\x49\\x43\\x41\\71\\x49\\103\\112\\103\\144\\x57\\x6" ascii
      $s8 = "\\x64\\x58\\x4a\\163\\132\\107\\x56\\x6a\\142\\x32\\122\\x6c\\113\\103\\122\\x33\\132\\127\\x49\\x75\\112\\107\\x6c\\165\\x61\\x" ascii
      $s9 = " goto nhPFr; PWUdh: Wca3D: goto mfc5z; NlHXL: echo \"\\x3c\\x70\\x72\\145\\x3e\"; goto k85_a; SpxzD: eval(base64_decode($ik04L))" ascii
      $s10 = "x49\\103\\x52\\161\\x64\\x57\\122\\61\\x62\\x43\\x41\\x67\\x49\\104\\x30\\147\\x49\\x6c\\x64\\124\\x54\\x79\\101\\x79\\114\\x6a" ascii
      $s11 = "164\\x74\\160\\x3a\\57\\57\\x6d\\x69\\x63\\150\\x61\\145\\x6c\\144\\141\\167\\x2e\\x6f\\162\\147\\40\\x20\\40\\62\\60\\60\\66\\x" ascii
      $s12 = "6\\x56\\126\\x4a\\112\\111\\x6c\\x30\\x37\\104\\x51\\x6f\\147\\x49\\x43\\x52\\60\\x59\\130\\112\\x6e\\132\\x58\\121\\x67\\111\\1" ascii
      $s13 = "03\\155\\154\\155\\x49\\x43\\x67\\153\\x64\\x6d\\x6c\\x7a\\x61\\130\\122\\152\\x49\\x44\\60\\71\\111\\x43\\111\\x69\\x4b\\123\\x" ascii
      $s14 = "3\\x49\\147\\x50\\123\\101\\x6b\\130\\61\\116\\x46\\125\\x6c\\x5a\\106\\x55\\x6c\\163\\151\\x55\\x6b\\126\\x4e\\x54\\61\\x52\\10" ascii
      $s15 = "x2e\\160\\150\\x70\\77\\x63\\x6d\\144\\75\\143\\141\\x74\\53\\57\\x65\\164\\x63\\x2f\\160\\141\\x73\\163\\x77\\x64\\12\\12\\74" ascii
      $s16 = "49\\151\\x58\\x54\\x73\\x4e\\103\\x69\\x41\\x67\\112\\x48\\144\\154\\131\\151\\101\\147\\111\\x43\\x41\\147\\x50\\123\\x41\\153" ascii
      $s17 = "0\\x74\\164\\160\\72\\x2f\\57\\x74\\x61\\162\\x67\\145\\164\\x2e\\143\\157\\x6d\\x2f\\163\\x69\\x6d\\160\\154\\x65\\x2d\\x62\\14" ascii
      $s18 = "3\\x44\\x6f\\x76\\x4c\\171\\x52\\x30\\x59\\130\\x4a\\156\\132\\x58\\121\\x67\\131\\156\\x6b\\147\\112\\110\\x5a\\x70\\x63\\62\\1" ascii
      $s19 = "a\\106\\125\\154\\x73\\x69\\123\\x46\\x52\\x55\\x55\\106\\x39\\x49\\x54\\61\\x4e\\x55\\x49\\154\\60\\x37\\104\\121\\x6f\\x67\\11" ascii
      $s20 = "06\\71\\x77\\x59\\130\\x4e\\172\\111\\152\\163\\x4e\\x43\\151\\x41\\x67\\141\\x57\\131\\x67\\x4b\\x43\\x46\\154\\142\\x58\\x42" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 10KB and
      8 of them
}

rule CgiMaster970ca01e_50a8_4c0f_bc60_ecde2b7546fe {
   meta:
      description = "php - file CgiMaster970ca01e-50a8-4c0f-bc60-ecde2b7546fe.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "fa5ddc1b65fba83ae856c926bac142273939c14903123070f191875d2568f5d3"
   strings:
      $x1 = "<?php ${\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"x\\x73\\x6a\\x6cn\\x6a\\x6e\"]=\"\\x6din\";${\"\\x47LOB\\x41LS\"}[\"\\x65ov" ascii
      $s2 = "x74\\x66sg\\x74uga\"]}=fopen(\"cgi.log\",\"\\x77+\");${${\"G\\x4c\\x4f\\x42\\x41\\x4cS\"}[\"\\x61\\x72\\x62\\x75\\x6b\\x76\\x74" ascii
      $s3 = "\\x3c\\x69m\\x67 \\x73r\\x63\\x3d\\x22https://ww\\x77.spy\\x68ac\\x6b\\x65\\x72z.\\x63\\x6fm/f\\x6f\\x72\\x75m/s\\x68t\\x6co\\x6" ascii
      $s4 = "69\\x65w\\x73 Inde\\x78es ExecC\\x47I\\n\\x41\\x64dT\\x79p\\x65 a\\x70pl\\x69\\x63atio\\x6e/x-h\\x74t\\x70\\x64-cgi \\x2e\\x61" ascii
      $s5 = "\\x32\\x31\\x6cX2R\\x70c\\x69\\x41\\x39IG\\x39z\\x4cm\\x64ld\\x47\\x4e3\\x5a\\x43\\x67\\x70\\x43gp0c\\x6e\\x6b6CiAgICBvc\\x795" ascii
      $s6 = "\\x61\\x72ge\\x74\\x3d\\x22\\x5fbl\\x61nk\\\"\\x3e\\x50e\\x72l\\x20I\\x7ao\\x63\\x69n C\\x67\\x69</a\\x3e\\x3c/\\x63en\\x74er>\"" ascii
      $s7 = "x6bok\\x64\\x6f\\x73\\x79a\";error_reporting(0);$gbamnge=\"\\x77\\x69\\x6er\";echo\"\\x3c\\x68tm\\x6c>\\x3c\\x66orm\\x20met\\x68" ascii
      $s8 = "\\x530\\x74\\x4cS0\\x74LS\\x30tLS0\\x74\\x4cS\\x30tLS0\\x74L\\x530tLS\\x30tL\\x53\\x30t\\x4cS0t\\x4c\\x530tL\\x530t\\x4cQp\\x7a" ascii
      $s9 = "61ndle\\x72\\x20\\x63g\\x69-script .\\x61\\x6cfa\";fwrite(${${\"G\\x4c\\x4fB\\x41\\x4c\\x53\"}[\"\\x79\\x75\\x64w\\x6c\\x6bhls\"" ascii
      $s10 = "\\x56zd\\x57x0\\x49C\\x34\\x39\\x49CI8dG\\x51+\\x49\\x694\\x6dRmls\\x5aU\\x78h\\x633R\\x4eb2\\x52\\x70Z\\x6dllZC\\x67k\\x5aCk\\x" ascii
      $s11 = "e\\x72\\x3e\";}if(isset($_POST[\"cgi\\x34\"])){$bibdqsp=\"\\x64\\x6f\\x73y\\x61\";${\"\\x47\\x4c\\x4f\\x42\\x41\\x4cS\"}[\"\\x68" ascii
      $s12 = "ewZ\\x57N\\x70Z\\x6dllZ\\x43B\\x6da\\x57\\x78l\\x49\\x47Zy\\x6220\\x67\\x64\\x47hlI\\x47R\\x70c\\x32\\x73\\x67\\x59W\\x35kI\\x48" ascii
      $s13 = "cent\\x65\\x72\\x3e\";}if(isset($_POST[\"c\\x67i6\"])){mkdir(\"alfa\\x63\\x67\\x69\\x32\");${\"G\\x4c\\x4fBA\\x4c\\x53\"}[\"m\\x" ascii
      $s14 = "w\\x5a\\x57\\x4epZ\\x6dllZ\\x43wg\\x63\\x48\\x4a\\x70b\\x6e\\x51\\x67\\x64\\x47hlI\\x47\\x52\\x76\\x64\\x325sb2F\\x6b\\x49\\x47Z" ascii
      $s15 = "/\\x68tml\\x3e\";$qbsiukbi=\"\\x6c\\x69\\x6e\\x72\";if(isset($_POST[\"\\x63gi\\x31\"])){${\"\\x47\\x4c\\x4f\\x42A\\x4c\\x53\"}[" ascii
      $s16 = "Te\\x6c\\x6ee\\x74\\x3c/\\x61\\x3e</\\x63ente\\x72\\x3e\";}if(isset($_POST[\"c\\x67\\x693\"])){mkdir(\"\\x63\\x67\\x69\\x74el\\x" ascii
      $s17 = "\\x44\\x31\\x6eZXRncmdp\\x5a\\x43\\x67\\x6b\\x5a\\x32lkK\\x54s\\x4b\\x43Q\\x6bJ\\x63m\\x560\\x64\\x58\\x4a\\x75IC\\x52u\\x59\\x5" ascii
      $s18 = "\\x47\\x52h\\x64GE\\x67P\\x53Bz\\x65\\x58\\x4d\\x75\\x63\\x33Rk\\x623V\\x30\\x4cmd\\x6c\\x64\\x48\\x5ahb\\x48\\x56lKCk\\x4b\\x49" ascii
      $s19 = "x68dG\\x6cv\\x62\\x6a\\x39h\\x50W\\x78\\x76\\x5a\\x3291\\x64\\x43I+\\x54\\x47\\x39\\x6eb3\\x56\\x30P\\x439h\\x50\\x69B\\x38\\x43" ascii
      $s20 = "67\\x4aGZp\\x62G\\x55\\x67\\x50SBza\\x47\\x6cmd\\x44\\x73\\x4bCWl\\x6dK\\x43\\x31m\\x49\\x43\\x52\\x6d\\x61\\x57\\x78lKQo\\x4aew" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule wso_latesta4739580_594c_425f_b78d_d139418911c9 {
   meta:
      description = "php - file wso-latesta4739580-594c-425f-b78d-d139418911c9.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "648f751cff4a8e1be7c9d3bd839d75f4fbafe6096e9eb8291ed9a798941501b1"
   strings:
      $x1 = "$eval=(\"?>\".gzuncompress(base64_decode(\"eJztvftb27jyOPwz53n2fxDenHWyDbnRdlsgaSmFli6Flkuv9Jt1EidxcWKv7RBot//7OzOSbPmS4AR2zznP+" ascii
      $s2 = "q+jySjq2XFr/0SaATqdc9uA7up/5YdumPitOnJYnUfg3t76we4ggcEolQyMZO75ESRaLJQcLJWbARxh0bpyEXhJV/Uc7epelsImTRqeW4Vy4pGWDVilc4IF4xfoMcUjb" ascii
      $s3 = "a9hr5MDcCBw3gRE90mRdga7oO9+ZyO33+5tphhqNBhXwXWNcHtbLhoQXjcBWrRGuLIxxEMJxLtempjUYArMdsuEod1j/Dl89+Lpmm/1g44EL6xrHButaNKlr9Hqw7ttg" ascii
      $s4 = "O3Y0Gddd+WZbnY0qPgYfu1iGhy/J3U7hf03P9gQl+oy8AEtJky5lxQJ0PO+6Uqkw9Qw5uWEzB1RDVEyeeBqo24bIKe4CR5Vj0b4vPwclLaroihPlCJTwzsdUYZhaieas" ascii
      $s5 = "IrwXr8n4RXMaNjCLSrCkA5LVW9WeeVnF7kW3HrNftPieeNziQ+zRPXaa6zNjcsX+YgPPdBlnil5cR6MvaZmK+8/UCpQ251e9m1X1rqh6zHK7qfbdzNorCet3L47uAuLo" ascii
      $s6 = "bnBdLLRPdo/f7R5/1l+enr5pn8G39vaL3cNT/UupxL7/9C8GPwWg420PzHHgAz7D84zrovbCcQa2qZWZdmJPPBc/vD45fOYE+Mky2obXHVqXpodfPxrjnnmFn46NUceG" ascii
      $s7 = "O94/waGTD/kSk1a8I92w3b3khJVie85o7wfu3S49oUaeg09TVHpV8f7lnY7zMG5KPq7Jr6v620b8jXVY1lIlvHe/cypw03pafX70rjdLL4ddvyFJ5CS17DwmiIg7LO5+" ascii
      $s8 = "vH0kExu0r0AVtXt5Ftpcte6bWMXQfOZ0MLc9nozASB74xdIT+o6brfisUK20ETG1uUwzCpaEbIiDNvQ7pxtbD+eVEAolD45c4sDoqucdv7h4B816Nwl/4u3IW087eXn0" ascii
      $s9 = "eDC1eFhQiSBUSqqNwOMDBmpCeJmBKpodfrgXA9gUTBmRblihLo9zy5bRNr3KkhOTMQ8TD5nMiWmUiUlekxOOn4QroJGetviwpliTsFT2FMTLjaK4Q2x1jPN6aQ2GNvwL" ascii
      $s10 = "YvTCtCVmoYTCkK2bmi/+HkUgO3NiHKhT3dyOX7jI0+Gz+nHUjef1Yj3sxWkg2V02dXnw5047Tf758Qd+KvQ6Ijo3dEjFtpXyXlcHeNZaoZdIbreCUkJHi3pqF9OiPR4l" ascii
      $s11 = "oQFCSSdPZR7fikQjF4167S7qMV9U9UVHeXZFbiCy6FAPieSR0qKjPI78Bs6XGeCInKuRXPwvOsSl5HMPh/qiYzw/5tuO6UZ+9VFfdFTPpXVDvZYd3mqz3zD7LTq4wTys" ascii
      $s12 = "fUKdlhQh6Tm+tNHETgGuiRqR6xy989oi+o844xMTNVtEW1msacJz/UCjuSQVI77nOEG4s1WA6SAMUWky5Vuqez7RmKoF9J8bD/r9Wk1vFd9DERPLlIQi0DbisKhNini8" ascii
      $s13 = "OQhTswQR7hOe+czo0ZIaN2FGRrD6T5qLVM2FmptKRO0tQmKjxb9WnmlBLd/86g11C9xNd2L0zdc4asRt8RglhBFM8DkeYzX71jg+c4hJmco/xd8gCgxBwtuQ9e6VYoHw" ascii
      $s14 = "NWfWr2Bo+WKVrbVwNuXd1zY6pt3U3hiwphTTp8b5ik/BjM+YVAi6GadMlRA93PSg47P9N7IlwyERrt01/re9/fz5sfZFdhJefMe2cFM8XVxd+b8+Ot2l0lzCckSj1OAX" ascii
      $s15 = "NwLYH7uycmy9BoW56AywwKDPKyWx0bLYN/G/zaiQJ1pnFihCQsNkjj/Ka2TkQbeAPNczv1P37hsjy77eEIIoh7JBNraqcpxv+V3PcoMWX1RfGh7rttF5jUoClY/vml3L" ascii
      $s16 = "DciB3E1e3/p9qLCsaTaTsv5QBin1rMuKaOrvLMSKGDlgSD8D3fr6OuGAumInWUM/Al/5bYydscnzNoYOSDoNAXhMz7YEWGVkh1XeqIe1pXaWXEVMQesh0r7tTDdgkRU4" ascii
      $s17 = "5BinlhHVuZnIkq4phUgjB5UlBr2g8iB/VZZcUCpE8lRlydVkLt217CJSIL+fg8KSi0ikkLchll1HRjRytMMyC0qwn3MO8GWWkZEu+WSOeznNgyXGeOTgz0diiRHOt3Ow" ascii
      $s18 = "zEbT2kphZFyF6PHvvYgijb0VOUbjdRfE+Qhq1jZh5DxE6W+GAyd6NVv/EPZnvkKpq8Iho5U/38SrwFos5EpgWlnpeKZxwQF/cOSeQeoF/xTrZSIuH5CiIRuNWH3Sczeq" ascii
      $s19 = "rHPkheKwPpriOr8FVpXPvElgQnfpmtnPpmTEc3sOf0U19arUselP7GCmN407KiioeE6gZZJMFGBpepcwQnIU9QmSX5kU7nBhRRK4qaP1AzcMDI6OQnVQLHskloLllgv4" ascii
      $s20 = "xjbiNW7p9zDGGdYL4+ZvLYolVTUFj4wTcQ9CR4RjDJcSM6G7ElrLHFKJNSuraPOxYSkzCHFWktH/AiC2NpZJJBaB34dVVldE2eHCsrXluDSbCcy0Zdfagd9bVZ6ThKDd" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 90KB and
      1 of ($x*) and 4 of them
}

rule small61fcfcb7_2b36_4ed8_99b7_8ed21706190e {
   meta:
      description = "php - file small61fcfcb7-2b36-4ed8-99b7-8ed21706190e.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "1b12bf14fa0ce23b7bd1c42484ba00b7b2e2bd80eac2dc532d6986d2b8babbdf"
   strings:
      $s1 = "dGNoX2FycmF5JzskSUlJSUlJSUkxbDExPSdteXNxbF9xdWVyeSc7JElJSUlJSUlJMWwxbD0nbXlzcWxfY29ubmVjdCc7JElJSUlJSUlJMWxJST0nb2JfZmx1c2gnOyRJ" ascii /* base64 encoded string 'tch_array';$IIIIIIII1l11='mysql_query';$IIIIIIII1l1l='mysql_connect';$IIIIIIII1lII='ob_flush';$I' */
      $s2 = "bGw9J2ZpbGVvd25lcic7JElJSUlJSUlJbGxsST0ncG9zaXhfZ2V0cHd1aWQnOyRJSUlJSUlJSWxsSWw9J3N1YnN0cic7JElJSUlJSUlJbGxJST0nc2l6ZW9mJzskSUlJ" ascii /* base64 encoded string 'll='fileowner';$IIIIIIIIlllI='posix_getpwuid';$IIIIIIIIllIl='substr';$IIIIIIIIllII='sizeof';$III' */
      $s3 = "OyRJSUlJSUlJSUkxSWw9J2Jhc2U2NF9kZWNvZGUnOyRJSUlJSUlJSUlsMUk9J2Jhc2VuYW1lJzskSUlJSUlJSUlJbGxJPSdzdHJ0b2xvd2VyJzskSUlJSUlJSUlJbEkx" ascii /* base64 encoded string ';$IIIIIIIII1Il='base64_decode';$IIIIIIIIIl1I='basename';$IIIIIIIIIllI='strtolower';$IIIIIIIIIlI1' */
      $s4 = "SUlJbElJMWw9J215c3FsX2Nsb3NlJzskSUlJSUlJSWxJSTFJPSdmZmx1c2gnOyRJSUlJSUlJbElJbDE9J2FkZHNsYXNoZXMnOyRJSUlJSUlJSTExMWw9J215c3FsX2Zl" ascii /* base64 encoded string 'IIIlII1l='mysql_close';$IIIIIIIlII1I='fflush';$IIIIIIIlIIl1='addslashes';$IIIIIIII111l='mysql_fe' */
      $s5 = "SUlJSTExMT0naHRtbHNwZWNpYWxjaGFycyc7JElJSUlJSUlJSTExST0ncmVhbHBhdGgnOyRJSUlJSUlJSUkxbDE9J2NoZGlyJzskSUlJSUlJSUlJMWxsPSdpc19kaXIn" ascii /* base64 encoded string 'IIII111='htmlspecialchars';$IIIIIIIII11I='realpath';$IIIIIIIII1l1='chdir';$IIIIIIIII1ll='is_dir'' */
      $s6 = "SUlJSUlJSTFJMTE9J29iX3N0YXJ0JzskSUlJSUlJSUkxSTFsPSdnemVuY29kZSc7JElJSUlJSUlJMUkxST0naGVhZGVyJzskSUlJSUlJSUkxSUkxPSdjb3B5JzskSUlJ" ascii /* base64 encoded string 'IIIIIII1I11='ob_start';$IIIIIIII1I1l='gzencode';$IIIIIIII1I1I='header';$IIIIIIII1II1='copy';$III' */
      $s7 = "bDE9J2ZvcGVuJzskSUlJSUlJSUlsMWxJPSdyZWFkbGluayc7JElJSUlJSUlJbDFJMT0naXNfbGluayc7JElJSUlJSUlJbDFJbD0nZmlsZW10aW1lJzskSUlJSUlJSUls" ascii /* base64 encoded string 'l1='fopen';$IIIIIIIIl1lI='readlink';$IIIIIIIIl1I1='is_link';$IIIIIIIIl1Il='filemtime';$IIIIIIIIl' */
      $s8 = "MUlJPSdkYXRlJzskSUlJSUlJSUlsbDExPSdmaWxlc2l6ZSc7JElJSUlJSUlJbGwxbD0ncHJpbnRmJzskSUlJSUlJSUlsbDFJPSdmaWxlZ3JvdXAnOyRJSUlJSUlJSWxs" ascii /* base64 encoded string '1II='date';$IIIIIIIIll11='filesize';$IIIIIIIIll1l='printf';$IIIIIIIIll1I='filegroup';$IIIIIIIIll' */
      $s9 = "SUlJSUkxSUlsPSdmY2xvc2UnOyRJSUlJSUlJSTFJSUk9J2Z3cml0ZSc7JElJSUlJSUlJbDExbD0nZnJlYWQnOyRJSUlJSUlJSWwxMUk9J2Zlb2YnOyRJSUlJSUlJSWwx" ascii /* base64 encoded string 'IIIII1IIl='fclose';$IIIIIIII1III='fwrite';$IIIIIIIIl11l='fread';$IIIIIIIIl11I='feof';$IIIIIIIIl1' */
      $s10 = "SUlJSUlsSTFJPSdzb3J0JzskSUlJSUlJSUlsSWwxPSdjbG9zZWRpcic7JElJSUlJSUlJbElsST0ncmVhZGRpcic7JElJSUlJSUlJbElJMT0nb3BlbmRpcic7JElJSUlJ" ascii /* base64 encoded string 'IIIIIlI1I='sort';$IIIIIIIIlIl1='closedir';$IIIIIIIIlIlI='readdir';$IIIIIIIIlII1='opendir';$IIIII' */
      $s11 = "koqckuIbgYofvHobxQ/gbpUf2ElsPYEAkoqckuIb0oVKzV2kQV2kQV2kQV2ky4mcj2egp7/y0HPkyH7gDHoJDQUDT9MS09BxKV2kQV2kQV2kyrEAyw2aKcDAwbK/r2Uy" ascii
      $s12 = "QV2kQV2kQVEBAX8BT4V3k6+J54ms7S8A56EbCYorCHP/TX87KQlKnmP7yS+24uBTk6+J54msPYEAkW8kvWI7BX8gJH87KW8khWmShQekQV2kQV2kQVpeAXmKnm0D460Q" ascii
      $s13 = "DoVegQDi7peB0wlSCpKg2Wei7peBCce78b77r7m3SQlShQekQV2kQV2kyV2kQX/yDoVG0omS09MSCce78b77r7m3972ArQlKhWMASXMWnm0D4QekQV2kQV2kyV2kQXLD" ascii
      $s14 = "QX/ylopDgQDiwQl6PQekQV2kQV2kyV2kQX/yDoVegQDi7peB0wlSCpKg2Wei7peBCce78b77r7m3SQlShQekQV2kQV2kyV2kQX/yDoVG0omS09MSCce78b77r7m3972A" ascii
      $s15 = "vHobxQ/gbpUf2ElsB6ofvs+b0oVKzQ/gbpUf2ElsB6ofvs+b0opx0Qvy4Q8cMwEkvS+7D4mcj2egp7/y0H8W0oVKzQ/gbpUf2ElsK6Mss9MS09BxKY8gvsLUTSqfksmC" ascii
      $s16 = "2Wei7peBCce78b77r7m3SQlShQekQV2kQV2kyV2kQX/yDoVG0omS09MSCce78b77r7m3972ArQlKhWMASXMWnm0D4QekQV2kQV2kyV2kQXLDKcDAwbK/r2Uy0V2kQV2k" ascii
      $s17 = "0HoHJX/g+6EAUHVss9MS09BxKHoHJX/g+6EAUHpUQV2kQV2kQV2kQVEBxQ87+6EAjsP/ysE2T9BxK6EfDYEghwEkvS+7D4mcj2egp7/y06EfDYEghQUDTwlcj2egp7/y" ascii
      $s18 = "iWedTXPseHEHJ6+7lwmgDYocyHpGfmNAdHocJW8JDsIadHo/UYo6gomQLX+iDHEiDZ7ciS87SWM3NX+iDHEiDw7BMs87Gsmgxs8Uy9l3NY8/lS+7DwosTXPc5sqrdrpW" ascii
      $s19 = "BHpUxYEcKHEGtLbxOYEiBsobCXP/dHpUSQqs5SPdjH8klomSCsIkBHpUxYEcKHEGCsP/ysE2gomS09+7NY8OCQekQV2kQV2kQVpeAXLdk6+J5WmsSQl3vYoTkwpelrLG" ascii
      $s20 = "XQ+cMo+cUXoa0opx0Qvy4QIcJ6PAko+cUXoagYofvHobxQ/gbpUf2ElsD6EQyH7gKsEUBQUDTwlcj2egp7/y0s8/MX87jHI7dSmss9MS09BTTHMCJ4e3duofAX/gvHEA" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 80KB and
      8 of them
}

rule b374v2_8_b374k09d33d31_57c0_4462_9be5_0802e986f128 {
   meta:
      description = "php - file b374v2.8-b374k09d33d31-57c0-4462-9be5-0802e986f128.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "7eb941572b3d49a1a24a32b8bbedef9558d0f77ddeddeeb09715ea72a73bdcd1"
   strings:
      $x1 = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
      $s2 = "SUlJSUlJbDExPSdhcnJheV9tYXAnOyRJSUlJSUlJSUlsMWw9J2FycmF5X21lcmdlJzskSUlJSUlJSUlJbGwxPSdleGlmX3JlYWRfZGF0YSc7JElJSUlJSUlJSWxJMT0n" ascii /* base64 encoded string 'IIIIIIl11='array_map';$IIIIIIIIIl1l='array_merge';$IIIIIIIIIll1='exif_read_data';$IIIIIIIIIlI1='' */
      $s3 = "Zmxvb3InOyRJSUlJSUlJbDFJSUk9J2JpbjJoZXgnOyRJSUlJSUlJbGwxbDE9J2ZjbG9zZSc7JElJSUlJSUlsbDFsbD0nZndyaXRlJzskSUlJSUlJSWxsMWxJPSdmb3Bl" ascii /* base64 encoded string 'floor';$IIIIIIIl1III='bin2hex';$IIIIIIIll1l1='fclose';$IIIIIIIll1ll='fwrite';$IIIIIIIll1lI='fope' */
      $s4 = "JzskSUlJSUlJbGxJSWwxPSd0b3VjaCc7JElJSUlJSWxsSUlsbD0nc3RydG90aW1lJzskSUlJSUlJbGxJSUkxPSdkZWNvY3QnOyRJSUlJSUlsbElJSWw9J2NobW9kJzsk" ascii /* base64 encoded string '';$IIIIIIllIIl1='touch';$IIIIIIllIIll='strtotime';$IIIIIIllIII1='decoct';$IIIIIIllIIIl='chmod';$' */
      $s5 = "Y2xlYXJzdGF0Y2FjaGUnOyRJSUlJSUlJSUlsSWw9J2luaV9zZXQnOyRJSUlJSUlJSUlsSUk9J3NldF90aW1lX2xpbWl0JzskSUlJSUlJSUlJSTExPSdvYl9zdGFydCc7" ascii /* base64 encoded string 'clearstatcache';$IIIIIIIIIlIl='ini_set';$IIIIIIIIIlII='set_time_limit';$IIIIIIIIII11='ob_start';' */
      $s6 = "cnJheV91bnNoaWZ0JzskSUlJSUlJSTExSUkxPSdjaGRpcic7JElJSUlJSUkxMUlJST0nbmF0Y2FzZXNvcnQnOyRJSUlJSUlJMWwxSUk9J3N0cnBvcyc7JElJSUlJSUkx" ascii /* base64 encoded string 'rray_unshift';$IIIIIII11II1='chdir';$IIIIIII11III='natcasesort';$IIIIIII1l1II='strpos';$IIIIIII1' */
      $s7 = "PSdzdHJ0b3VwcGVyJzskSUlJSUlJbDFJMUlJPSdwYWNrJzskSUlJSUlJbDFJbGwxPSdoaWdobGlnaHRfc3RyaW5nJzskSUlJSUlJbDFJbGxsPSd3b3Jkd3JhcCc7JElJ" ascii /* base64 encoded string '='strtoupper';$IIIIIIl1I1II='pack';$IIIIIIl1Ill1='highlight_string';$IIIIIIl1Illl='wordwrap';$II' */
      $s8 = "SUlJSUlsSUkxSTE9J215c3FsX3F1ZXJ5JzskSUlJSUlJbElJbDFsPSdvZGJjX2Nvbm5lY3QnOyRJSUlJSUlsSUlsMUk9J3BnX2Nvbm5lY3QnOyRJSUlJSUlsSUlsbEk9" ascii /* base64 encoded string 'IIIIIlII1I1='mysql_query';$IIIIIIlIIl1l='odbc_connect';$IIIIIIlIIl1I='pg_connect';$IIIIIIlIIllI=' */
      $s9 = "bic7JElJSUlJSUlsbDFJbD0ndW5saW5rJzskSUlJSUlJSWxsMUlJPSdpc19maWxlJzskSUlJSUlJSWxJMTFJPSdyYXd1cmxlbmNvZGUnOyRJSUlJSUlJbEkxbGw9J3Jh" ascii /* base64 encoded string 'n';$IIIIIIIll1Il='unlink';$IIIIIIIll1II='is_file';$IIIIIIIlI11I='rawurlencode';$IIIIIIIlI1ll='ra' */
      $s10 = "PSdyZWFkZGlyJzskSUlJSUlJSTFJbEkxPSdvcGVuZGlyJzskSUlJSUlJSTFJSTExPSdwY2xvc2UnOyRJSUlJSUlJMUlJMWw9J2ZyZWFkJzskSUlJSUlJSTFJSTFJPSdm" ascii /* base64 encoded string '='readdir';$IIIIIII1IlI1='opendir';$IIIIIII1II11='pclose';$IIIIIII1II1l='fread';$IIIIIII1II1I='f' */
      $s11 = "SUlJSWwxSUlsbD0nZmlsZWF0aW1lJzskSUlJSUlJbDFJSWxJPSdmaWxlY3RpbWUnOyRJSUlJSUlsMUlJSWw9J2Rpcm5hbWUnOyRJSUlJSUlsbDExSTE9J2lzX3VwbG9h" ascii /* base64 encoded string 'IIIIl1IIll='fileatime';$IIIIIIl1IIlI='filectime';$IIIIIIl1IIIl='dirname';$IIIIIIll11I1='is_uploa' */
      $s12 = "SUlJSUlJSUlJbGw9J3RpbWUnOyRJSUlJSUlJSUkxbDE9J3N0cnRvbG93ZXInOyRJSUlJSUlJSUkxbGw9J3RyaW0nOyRJSUlJSUlJSUkxSTE9J2lzX2FycmF5JzskSUlJ" ascii /* base64 encoded string 'IIIIIIIIIll='time';$IIIIIIIII1l1='strtolower';$IIIIIIIII1ll='trim';$IIIIIIIII1I1='is_array';$III' */
      $s13 = "Y19jbG9zZSc7JElJSUlJSWxJbDFJMT0ncGdfY2xvc2UnOyRJSUlJSUlsSWwxSWw9J21zc3FsX2Nsb3NlJzskSUlJSUlJbElsMUlJPSdteXNxbF9jbG9zZSc7JElJSUlJ" ascii /* base64 encoded string 'c_close';$IIIIIIlIl1I1='pg_close';$IIIIIIlIl1Il='mssql_close';$IIIIIIlIl1II='mysql_close';$IIIII' */
      $s14 = "SWxJbGwxbD0nb2RiY19mZXRjaF9hcnJheSc7JElJSUlJSWxJbGwxST0ncGdfZmV0Y2hfcm93JzskSUlJSUlJbElsbGwxPSdtc3NxbF9mZXRjaF9yb3cnOyRJSUlJSUls" ascii /* base64 encoded string 'IlIll1l='odbc_fetch_array';$IIIIIIlIll1I='pg_fetch_row';$IIIIIIlIlll1='mssql_fetch_row';$IIIIIIl' */
      $s15 = "SUkxSTFJMT0nZ2xvYic7JElJSUlJSUkxSWwxMT0nY29weSc7JElJSUlJSUkxSWxsMT0ncm1kaXInOyRJSUlJSUlJMUlsbGw9J2Nsb3NlZGlyJzskSUlJSUlJSTFJbGxJ" ascii /* base64 encoded string 'II1I1I1='glob';$IIIIIII1Il11='copy';$IIIIIII1Ill1='rmdir';$IIIIIII1Illl='closedir';$IIIIIII1IllI' */
      $s16 = "bElJPSdtc3NxbF9maWVsZF9uYW1lJzskSUlJSUlJbElsSTFJPSdvZGJjX251bV9maWVsZHMnOyRJSUlJSUlsSWxJbDE9J3BnX251bV9maWVsZHMnOyRJSUlJSUlsSWxJ" ascii /* base64 encoded string 'lII='mssql_field_name';$IIIIIIlIlI1I='odbc_num_fields';$IIIIIIlIlIl1='pg_num_fields';$IIIIIIlIlI' */
      $s17 = "SUlJSUlJbGwxSTExPSdhcnJheV9maWx0ZXInOyRJSUlJSUlsbGxJSUk9J3JhbmQnOyRJSUlJSUlsbElsbGw9J3JlYWRmaWxlJzskSUlJSUlJbGxJSTExPSdpbXBsb2Rl" ascii /* base64 encoded string 'IIIIIIll1I11='array_filter';$IIIIIIlllIII='rand';$IIIIIIllIlll='readfile';$IIIIIIllII11='implode' */
      $s18 = "SUlJSUlJSUkxMUlJPSdwcmVnX3JlcGxhY2UnOyRJSUlJSUlJSWxJMUk9J3NoYTEnOyRJSUlJSUlJSTFsSUk9J3N0cmlwc2xhc2hlcyc7JElJSUlJSUlJMUkxMT0naW5p" ascii /* base64 encoded string 'IIIIIIII11II='preg_replace';$IIIIIIIIlI1I='sha1';$IIIIIIII1lII='stripslashes';$IIIIIIII1I11='ini' */
      $s19 = "bGxsMT0nc3RycnBvcyc7JElJSUlJSUkxbEkxbD0naXNfd3JpdGFibGUnOyRJSUlJSUlJMWxJbEk9J2Jhc2VuYW1lJzskSUlJSUlJSTFJMWxJPSdjb3VudCc7JElJSUlJ" ascii /* base64 encoded string 'lll1='strrpos';$IIIIIII1lI1l='is_writable';$IIIIIII1lIlI='basename';$IIIIIII1I1lI='count';$IIIII' */
      $s20 = "SUlJSUkxMWwxST0nZmlsZWdyb3VwJzskSUlJSUlJSTExbGxsPSdmaWxlb3duZXInOyRJSUlJSUlJMTFsbEk9J3Bvc2l4X2dldHB3dWlkJzskSUlJSUlJSTExSWxJPSdh" ascii /* base64 encoded string 'IIIII11l1I='filegroup';$IIIIIII11lll='fileowner';$IIIIIII11llI='posix_getpwuid';$IIIIIII11IlI='a' */
   condition:
      uint16(0) == 0x3f3c and filesize < 800KB and
      1 of ($x*) and 4 of them
}

rule Sincap1_0_encoded389efc72_ef10_4bfc_bfd5_72e010c0c838 {
   meta:
      description = "php - file Sincap1.0-encoded389efc72-ef10-4bfc-bfd5-72e010c0c838.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "c4ab4319a77b751a45391aa01cde2d765b095b0e3f6a92b0b8626d5c7e3ad603"
   strings:
      $s1 = "    |     Sincap 1.0 Shell- leetc0des.blogspot.com     |" fullword ascii
      $s2 = " echo \"\\x3c\\150\\164\\155\\154\\x3e\\12\\xa\\x3c\\150\\145\\141\\x64\\76\\12\\x3c\\x6d\\x65\\164\\141\\40\\150\\x74\\164\\160" ascii
      $s3 = " echo \"\\x3c\\150\\164\\155\\154\\x3e\\12\\xa\\x3c\\150\\145\\141\\x64\\76\\12\\x3c\\x6d\\x65\\164\\141\\40\\150\\x74\\164\\160" ascii
      $s4 = "\\x3b\\xa\\x24\\164\\157\\x70\\x6c\\x61\\x6d\\75\\42\\44\\x74\\157\\x70\\x6c\\x61\\155\\x24\\157\\x6b\\x75\\156\\x61\\156\\42\\x" ascii
      $s5 = "\\40\\x20\\x20\\40\\x3c\\x66\\x6f\\x6e\\164\\x20\\146\\x61\\143\\145\\75\\42\\x56\\145\\x72\\144\\x61\\x6e\\x61\\x22\\x20\\163" ascii
      $s6 = "\\141\\162\\147\\151\\156\\x68\\145\\151\\147\\150\\x74\\x3d\\42\\x30\\x22\\x3e\\xa\\xa\\74\\164\\x61\\142\\154\\x65\\40\\142\\x" ascii
      $s7 = "\\60\\142\\63\\x49\\x67\\x50\\123\\x41\\x6b\\x58\\x31\\x4e\\x46\\125\\x6c\\x5a\\x46\\x55\\x6c\\163\\151\\x55\\153\\x56\\x4e\\124" ascii
      $s8 = "\\x22\\x20\\154\\145\\x66\\164\\x6d\\x61\\x72\\x67\\x69\\156\\75\\42\\60\\42\\x20\\x72\\151\\x67\\x68\\x74\\x6d\\141\\162\\147" ascii
      $s9 = "\\143\\x69\\156\\147\\75\\42\\x30\\x22\\x20\\163\\164\\x79\\x6c\\x65\\x3d\\42\\142\\x6f\\x72\\144\\145\\x72\\x2d\\143\\157\\x6c" ascii
      $s10 = "\\55\\x77\\145\\151\\147\\x68\\164\\72\\40\\x37\\x30\\60\\x22\\x20\\143\\x6f\\x6c\\x6f\\162\\75\\42\\x23\\60\\x30\\x30\\60\\x30" ascii
      $s11 = "\\143\\x6f\\154\\157\\162\\75\\42\\43\\x45\\65\\x45\\65\\105\\x35\\x22\\40\\x61\\154\\x69\\x67\\x6e\\75\\42\\x6c\\145\\146\\164" ascii
      $s12 = "\\165\\142\\165\\x3c\\x62\\162\\x3e\\xa\\x20\\40\\40\\x20\\74\\163\\x70\\141\\156\\40\\x73\\164\\171\\154\\145\\x3d\\42\\x66\\x6" ascii
      $s13 = "\\141\\x46\\x39\\x77\\131\\x58\\x4e\\x7a\\x49\\x6a\\163\\116\\x43\\151\\101\\147\\x61\\x57\\x59\\147\\113\\103\\106\\x6c\\142\\x" ascii
      $s14 = "\\146\\164\\x22\\x20\\x76\\x61\\154\\151\\147\\x6e\\75\\42\\164\\x6f\\x70\\x22\\x3e\\12\\x20\\40\\x20\\x20\\x3c\\x66\\157\\156" ascii
      $s15 = "\\75\\x22\\x50\\162\\x6f\\147\\x49\\x64\\42\\40\\x63\\157\\x6e\\x74\\145\\156\\x74\\75\\x22\\106\\162\\157\\156\\x74\\120\\141" ascii
      $s16 = "\\x69\\42\\x29\\51\\173\\xa\\x69\\x66\\50\\44\\145\\x6b\\151\\x6e\\143\\151\\76\\x22\\x73\\x65\\x73\\163\\x5f\\x22\\51\\x7b\\12" ascii
      $s17 = "\\65\\x38\\x35\\42\\40\\163\\x74\\171\\x6c\\x65\\x3d\\42\\x66\\x6f\\x6e\\164\\55\\x73\\x69\\172\\145\\x3a\\40\\x32\\160\\164\\x2" ascii
      $s18 = "\\157\\154\\x6f\\x72\\75\\42\\x23\\102\\x36\\102\\x36\\x42\\66\\42\\76\\xa\\x20\\40\\x20\\40\\74\\146\\157\\156\\164\\x20\\x66" ascii
      $s19 = "\\76\\12\\40\\40\\x20\\40\\74\\x74\\x64\\x20\\167\\x69\\x64\\164\\x68\\x3d\\42\\x38\\45\\x22\\40\\142\\x67\\x63\\x6f\\154\\x6f" ascii
      $s20 = "\\61\\122\\x66\\126\\x56\\x4a\\x4a\\111\\x6c\\x30\\67\\104\\x51\\x6f\\x67\\x49\\103\\x52\\60\\131\\x58\\x4a\\x6e\\132\\x58\\121" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 50KB and
      8 of them
}

rule s72_Shell_v1_1_Codinga1d6a287_396d_414e_abed_127f136ea431 {
   meta:
      description = "php - file s72 Shell v1.1 Codinga1d6a287-396d-414e-abed-127f136ea431.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "fd47d071efe1962995b99b554d3884bc08e59dd2687c3086da0f1367137a126d"
   strings:
      $s1 = "SUlJSUlJSWxsST0naW5pX2dldCc7JElJSUlJSUlJSWxJMT0nY29weSc7JElJSUlJSUlJSUkxST0nY2xvc2VkaXInOyRJSUlJSUlJSUlJbDE9J3JlYWRkaXInOyRJSUlJ" ascii /* base64 encoded string 'IIIIIIIllI='ini_get';$IIIIIIIIIlI1='copy';$IIIIIIIIII1I='closedir';$IIIIIIIIIIl1='readdir';$IIII' */
      $s2 = "xCWmaCWmaOSm3JX8k0XNDM6+7hs87lWNGfmMaCWmaCWmaCw8H5X0bC6+gyXqWgWMf8cNaBrLaMwCD4WmaCWmaCWmaOs87Gs8/lHEeCSP7JH8ghXIKCS+kFHpDMrVWCSP" ascii
      $s3 = "2T4bTnmP7NY8OCWNABW8/yYEshwEfkX0ckSNieXqfi6V3m6S9t6oZL5EvL5V3mYoWCBiikY+kyH82CES9OY+AkXPcTwmgBwMWnm0D4HEAvHEkP4m/PYEAko+7GYofDSl" ascii
      $s4 = "ghsm3P6EfkwVQEHoQK6EiJWM3vsIkyHpDMHPghsmUvYoTk9MaGSIbMW8f5X8glwVWN9LaBrLCBWNimsoQJH8/hWec5SqkJW/7BX8gJHm3/H87MYEATS0fTXPkFZNB5HP" ascii
      $s5 = "lkaDVCQWx2RFUrcUdpRm5PZ3R6PScsJ0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5Ky8nKSk7ZXZhbC" ascii
      $s6 = "ynHEfxXla0WmaCWmaCWmaO60WCZvGfmMaCWmaCWmaCw8Wt2+JkX8BCc8kFYEiT9NB56NGCQvdk6+J5WmcpbUQQ2/cjcKkrc2i3p22C9+7NY8OCQlaCWmaCWmaCw8QlwC" ascii
      $s7 = "aCWLABwMHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9l" ascii
      $s8 = "Hh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9laOZ+WtSvSlW/fxHEAyWI6AZNeCb+gKYEi0W8QiWLAJW8JlHE6gWPUJYEADXvTNSP" ascii
      $s9 = "cwpDOBrLaBreOxQeOBpvaBpDOBrmCKpvaBreOBpvaBZmcwpvaBpvaBrLaTZmsJr+UrHVOGV7scf/TlHNkq6PfESLWqcEO+V/k62qfUYKf4p2iZYUaBu/cVrokKYL7mbE" ascii
      $s10 = "/yYEshwVQNHEiDHoWMwCD4WmaCWmaCw8QlwCD4WmaCWmaCWmaO6NGOHPghsm3P6EfkwVQLX+UT6l3p6EivWeUpWM3vYoTkwVWAWM3NX+A5SNDMWDH8rLaBrmWtEl37S8" ascii
      $s11 = "DMsIWMwCD4w8Uks8eCXP/dHpDMcD79c7Q37egVWM3NX+iDHEiDwVQfYEflXqf5H0bCc0Q5X0cb6EskWL2hrmWtLbxOXE7D6V3h6EUkwVQbSPg0VEbMW8f5X0ckX0bgWK" ascii
      $s12 = "T87EAvY7717Ki2r7Q8EL38c7Q8VEk67IfZV2f3Y+bl7PkQbD/0V2f392kL2PH7r/Hp7PdE2UsiVKkEckQcEL3x2/2A2Ek67IfZV2f3Y+/ofo/QbD/0V2f392kL2PH7r/" ascii
      $s13 = "kQV2kQV2kQV2kQrVKTWIy4YE6xQ8HTX82CWpDCWMGMQM6KHPkyHVaJwVaMZMGM4bTk6+J5WmSO6V3D6oQ0HobgWkgMX8/hYlWCYIQkHNDMQlGKHPkyHVG0WNG0ZMcPYE" ascii
      $s14 = "WCsP/ysE2gWy9I6EvL5S9tsr9gSMeMwNB5HPghsLGOHPghsm3NX+A5SNDMWDH8rLaBrmWtw8QlwCD4QPiMSqanw8QlwNB5HPghsLGOZqatLbxCWmaCWmaOZ+H5SPDtLb" ascii
      $s15 = "A+c/21S2sTcPiwHqcFwVSyQD/mbDc/cKsWV2TZpeU9pU3c2kf277HoE/kY6EQNH87PH+JTYPdyXEi5SI/lSqcUs0sGuoxBrpWvfL2+fvCi4lO04VKT9+HNX8gvHVCKpv" ascii
      $s16 = "ADHoJD6oQk6V3vYoTkwVWqrmWCXP/dHpDM6+gdXE/hHmWCSPgqSvDMrMWC6+gySvDMfLrMWLGOZqckuIcJSP7JwMaO60WtLbxO60Wtw8khSI7DWIciS82gW0fU6PUTsm" ascii
      $s17 = "TB6vQyr8WvVEsr2D/1H/J9X8fTbocQbUQxH/JVXUCvbPJNrDUTpqs5HDkIX8UQb+sxEkSAs+cWY+g4V8cyEEk1SekWS+sccv/x67sqXDkdY8JNX7WvE7J4X8/I7PJKX7" ascii
      $s18 = "aBrLaMwNAMwNAPX+iDW8HJ6+2gWKf5XEkNW/fJX0rCp7rMWIfTuP2gWNeMwMHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60" ascii
      $s19 = "Hh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9lHh60fB9BD4WmaCWmaCw8H5X0bC6+gyXqWgWMf8cN" ascii
      $s20 = "D4WmaCWmaCWmaPXPQvSLyOZ+H5X0btwmgPX+iDwNABW8/yYEshwVQNHEiDHoWMwNAPXqQdW8Uks8J5HLDMS8gvsmWtLbxOSm3JX8k0XNDM6+7hs87lWNGfmNAPX+iDW8" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 30KB and
      8 of them
}

rule bayz21_priv_shell_v2103f26bc_b968_4180_9086_9fd9a3ef8afe {
   meta:
      description = "php - file bayz21-priv-shell-v2103f26bc-b968-4180-9086-9fd9a3ef8afe.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "de3dc662c11bfa98dce790c300c5215bb2c71311dd87249f1d18613ec05c1988"
   strings:
      $s1 = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
      $s2 = "SUlJSUkxSTE9J2lzX2FycmF5JzskSUlJSUlJSWxJSTFJPSdzdWJzdHInOyRJSUlJSUlJMWwxSUk9J3N0cnBvcyc7JElJSUlJSUlsMUkxST0nc3ByaW50Zic7JElJSUlJ" ascii /* base64 encoded string 'IIIII1I1='is_array';$IIIIIIIlII1I='substr';$IIIIIII1l1II='strpos';$IIIIIIIl1I1I='sprintf';$IIIII' */
      $s3 = "SUkxbD0nY3VybF9pbml0JzskSUlJSUlJMWwxMTFsPSdmcHV0cyc7JElJSUlJSTFsMTFsMT0nam9pbic7JElJSUlJSUkxSUlJMT0nZmdldHMnOyRJSUlJSUlJMUlJMUk9" ascii /* base64 encoded string 'II1l='curl_init';$IIIIII1l111l='fputs';$IIIIII1l11l1='join';$IIIIIII1III1='fgets';$IIIIIII1II1I=' */
      $s4 = "ST0nZm9wZW4nOyRJSUlJSUlsbElsbGw9J3JlYWRmaWxlJzskSUlJSUlJSWwxbElsPSdmaWxlc2l6ZSc7JElJSUlJSUkxbElsST0nYmFzZW5hbWUnOyRJSUlJSUkxSWxs" ascii /* base64 encoded string 'I='fopen';$IIIIIIllIlll='readfile';$IIIIIIIl1lIl='filesize';$IIIIIII1lIlI='basename';$IIIIII1Ill' */
      $s5 = "SWxJSUlJbD0nZGF0ZSc7JElJSUlJbElJbElJbD0nb2JfZmx1c2gnOyRJSUlJSUlsbElJSWw9J2NobW9kJzskSUlJSUlJSWxJMUlJPSdodG1sc3BlY2lhbGNoYXJzJzsk" ascii /* base64 encoded string 'IlIIIIl='date';$IIIIIlIIlIIl='ob_flush';$IIIIIIllIIIl='chmod';$IIIIIIIlI1II='htmlspecialchars';$' */
      $s6 = "bElJMUkxPSdteXNxbF9xdWVyeSc7JElJSUlJSWxJSWxJbD0nbXlzcWxfY29ubmVjdCc7JElJSUlJSWxsMWxsbD0naXNfcmVhZGFibGUnOyRJSUlJSUkxMUlsSWw9J2N1" ascii /* base64 encoded string 'lII1I1='mysql_query';$IIIIIIlIIlIl='mysql_connect';$IIIIIIll1lll='is_readable';$IIIIII11IlIl='cu' */
      $s7 = "SUlsSWw9J2luaV9zZXQnOyRJSUlJSUlJSUlsSTE9J2NsZWFyc3RhdGNhY2hlJzskSUlJSUlJSUlJbElJPSdzZXRfdGltZV9saW1pdCc7JElJSUlJSTFJbEkxST0nc2Vz" ascii /* base64 encoded string 'IIlIl='ini_set';$IIIIIIIIIlI1='clearstatcache';$IIIIIIIIIlII='set_time_limit';$IIIIII1IlI1I='ses' */
      $s8 = "aXNfZmlsZSc7JElJSUlJSTFJbElJbD0ncmVhbHBhdGgnOyRJSUlJSUlJMUlsbDE9J3JtZGlyJzskSUlJSUlJSUlJSTFsPSdiYXNlNjRfZGVjb2RlJzskSUlJSUlJMWxs" ascii /* base64 encoded string 'is_file';$IIIIII1IlIIl='realpath';$IIIIIII1Ill1='rmdir';$IIIIIIIIII1l='base64_decode';$IIIIII1ll' */
      $s9 = "STFsSWxJMT0nZmx1c2gnOyRJSUlJSUkxbElsSUk9J3ByZWdfbWF0Y2hfYWxsJzskSUlJSUlJMWxJSTExPSdlcmVnJzskSUlJSUlJMWxJSWxsPSdmaWxlJzskSUlJSUlJ" ascii /* base64 encoded string 'I1lIlI1='flush';$IIIIII1lIlII='preg_match_all';$IIIIII1lII11='ereg';$IIIIII1lIIll='file';$IIIIII' */
      $s10 = "87lwMWnm0D4jE7yS+7THMCKoDs/7/y0H8O0oVagwVa0S+UDSmSTWIy4HEfxXlaMw8fkX0ckSNGOSq3JXNi9bNxC78g5XIrCYEiTWIs5SPyCYPk16V3KYETJX8/hY+/hW" ascii
      $s11 = "JzskSUlJSUlJSWxJSWxsPSdpc19kaXInOyRJSUlJSUlJbGwxSWw9J3VubGluayc7JElJSUlJSUkxSWwxMT0nY29weSc7JElJSUlJSUlJSTFsbD0ndHJpbSc7JElJSUlJ" ascii /* base64 encoded string '';$IIIIIIIlIIll='is_dir';$IIIIIIIll1Il='unlink';$IIIIIII1Il11='copy';$IIIIIIIII1ll='trim';$IIIII' */
      $s12 = "bDExPSdiYXNlNjRfZW5jb2RlJzskSUlJSUlJSTFJbGxsPSdjbG9zZWRpcic7JElJSUlJSTFsbGxJST0nYXJyYXlfcHVzaCc7JElJSUlJSUlJSWwxbD0nYXJyYXlfbWVy" ascii /* base64 encoded string 'l11='base64_encode';$IIIIIII1Illl='closedir';$IIIIII1lllII='array_push';$IIIIIIIIIl1l='array_mer' */
      $s13 = "SUlsMWxsbD0nZmlsZXBlcm1zJzskSUlJSUlJSWwxMUlsPSdzaGVsbF9leGVjJzskSUlJSUlJSWwxMWxsPSdwYXNzdGhydSc7JElJSUlJSUlsMTFJMT0nZXhlYyc7JElJ" ascii /* base64 encoded string 'IIl1lll='fileperms';$IIIIIIIl11Il='shell_exec';$IIIIIIIl11ll='passthru';$IIIIIIIl11I1='exec';$II' */
      $s14 = "cmxfY2xvc2UnOyRJSUlJSUkxMUlsSUk9J2N1cmxfZXhlYyc7JElJSUlJSUlsSWxsbD0nc2l6ZW9mJzskSUlJSUlJMTFJSTExPSdjdXJsX3NldG9wdCc7JElJSUlJSTEx" ascii /* base64 encoded string 'rl_close';$IIIIII11IlII='curl_exec';$IIIIIIIlIlll='sizeof';$IIIIII11II11='curl_setopt';$IIIIII11' */
      $s15 = "SUk9J2ZpbGVtdGltZSc7JElJSUlJbElJMTExbD0nZmlsZXR5cGUnOyRJSUlJSUlsbDFsSUk9J2FycmF5X2RpZmYnOyRJSUlJSUlsSTExMWw9J3JlbmFtZSc7JElJSUlJ" ascii /* base64 encoded string 'II='filemtime';$IIIIIlII111l='filetype';$IIIIIIll1lII='array_diff';$IIIIIIlI111l='rename';$IIIII' */
      $s16 = "Z2UnOyRJSUlJSUlJMUlsbEk9J3JlYWRkaXInOyRJSUlJSUlJMUlsSTE9J29wZW5kaXInOyRJSUlJSUlJSWxJbGw9J2luX2FycmF5JzskSUlJSUlJMWxsSWxsPSdzb3J0" ascii /* base64 encoded string 'ge';$IIIIIII1IllI='readdir';$IIIIIII1IlI1='opendir';$IIIIIIIIlIll='in_array';$IIIIII1llIll='sort' */
      $s17 = "SUlJSUlJbGxJbD0nb2JfZW5kX2NsZWFuJzskSUlJSUlJSUlsbElJPSdvYl9nZXRfY29udGVudHMnOyRJSUlJSUlJbDExSUk9J3N5c3RlbSc7JElJSUlJSUlJSUkxMT0n" ascii /* base64 encoded string 'IIIIIIllIl='ob_end_clean';$IIIIIIIIllII='ob_get_contents';$IIIIIIIl11II='system';$IIIIIIIIII11='' */
      $s18 = "SUlJSUlJbElsMUlJPSdteXNxbF9jbG9zZSc7JElJSUlJSTExbDFsST0nbXlzcWxfZXJyb3InOyRJSUlJSUkxMWwxSUk9J215c3FsX2ZldGNoX2FycmF5JzskSUlJSUlJ" ascii /* base64 encoded string 'IIIIIIlIl1II='mysql_close';$IIIIII11l1lI='mysql_error';$IIIIII11l1II='mysql_fetch_array';$IIIIII' */
      $s19 = "bDE9J29iX2NsZWFuJzskSUlJSUlJSUlsSWwxPSdoZWFkZXInOyRJSUlJSUlsbElJMTE9J2ltcGxvZGUnOyRJSUlJSUlJSWxsSTE9J3ByZWdfbWF0Y2gnOyRJSUlJSUlJ" ascii /* base64 encoded string 'l1='ob_clean';$IIIIIIIIlIl1='header';$IIIIIIllII11='implode';$IIIIIIIIllI1='preg_match';$IIIIIII' */
      $s20 = "cmVudF91c2VyJzskSUlJSUlJSUlJMWwxPSdzdHJ0b2xvd2VyJzskSUlJSUlJSUkxSTExPSdpbmlfZ2V0JzskSUlJSUlJSWxJbElsPSdleHBsb2RlJzskSUlJSUlJSTEx" ascii /* base64 encoded string 'rent_user';$IIIIIIIII1l1='strtolower';$IIIIIIII1I11='ini_get';$IIIIIIIlIlIl='explode';$IIIIIII11' */
   condition:
      uint16(0) == 0x3f3c and filesize < 500KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _gel4y_encaab6f38e_97b2_4478_b22c_94126638effe_gel4y508f3686_7973_49ad_a07b_77c6dff29116_0 {
   meta:
      description = "php - from files gel4y-encaab6f38e-97b2-4478-b22c-94126638effe.php, gel4y508f3686-7973-49ad-a07b-77c6dff29116.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "bbb4095d217fe66365c4a5f9eaa8d44fe3abfc6fb735ad13b29ab5f2c3810d78"
      hash2 = "13c8927b3e19bdd61cf1889bccc675523cefdc15be24d22d0f065f55be4c20f1"
   strings:
      $s1 = "<script src=\"//code.jquery.com/jquery-3.5.1.slim.min.js\"></script>" fullword ascii
      $s2 = "<script src=\"//unpkg.com/sweetalert/dist/sweetalert.min.js\"></script>" fullword ascii
      $s3 = "68746d6c7370656369616c6368617273" ascii /* hex encoded string 'htmlspecialchars' */
      $s4 = "<!-- RandsX aka T1kus_g0t -->" fullword ascii
      $s5 = "707265675f73706c6974" ascii /* hex encoded string 'preg_split' */
      $s6 = "66696c656d74696d65" ascii /* hex encoded string 'filemtime' */
      $s7 = "6d6b646972" ascii /* hex encoded string 'mkdir' */
      $s8 = "<form method=\"post\"><div class=\"form-group\"><label for=\"n\">File name :</label><input type=\"text\" name=\"n\" id=\"n\" cla" ascii
      $s9 = "69735f66696c65" ascii /* hex encoded string 'is_file' */
      $s10 = "<small>Copyright &copy; 2021 - Powered By Indonesian Darknet</small>" fullword ascii
      $s11 = "66696c655f7075745f636f6e74656e7473" ascii /* hex encoded string 'file_put_contents' */
      $s12 = "70687076657273696f6e" ascii /* hex encoded string 'phpversion' */
      $s13 = "66696c6573697a65" ascii /* hex encoded string 'filesize' */
      $s14 = "69735f7265616461626c65" ascii /* hex encoded string 'is_readable' */
      $s15 = "72656e616d65" ascii /* hex encoded string 'rename' */
      $s16 = "66696c655f657869737473" ascii /* hex encoded string 'file_exists' */
      $s17 = "7068705f756e616d65" ascii /* hex encoded string 'php_uname' */
      $s18 = "66696c655f6765745f636f6e74656e7473" ascii /* hex encoded string 'file_get_contents' */
      $s19 = "69735f646972" ascii /* hex encoded string 'is_dir' */
      $s20 = "737472746f74696d65" ascii /* hex encoded string 'strtotime' */
   condition:
      ( uint16(0) == 0x3f3c and filesize < 40KB and ( 8 of them )
      ) or ( all of them )
}

rule _wso2_77af2ddf3_98e1_45d5_b018_61528d1b916e_wso2_8cb0c936b_b009_41a7_b503_5e323d207445_1 {
   meta:
      description = "php - from files wso2.77af2ddf3-98e1-45d5-b018-61528d1b916e.php, wso2.8cb0c936b-b009-41a7-b503-5e323d207445.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "ed45d742830cbd157ab612c564b5c6e567971ab441e992da73ef3aac9b8bab24"
      hash2 = "fd953c4f799a538beb99962b0249f7a3a2dfc81345d7f47fa8842e3e76197b0e"
   strings:
      $s1 = "SUlJSUlJMTFsMT0nZnRwX2xvZ2luJzskSUlJSUlJSUkxMWxsPSdmdHBfY2xvc2UnOyRJSUlJSUlJSTExbEk9J2lzX2FycmF5JzskSUlJSUlJSUkxMUkxPSdmaWxlJzsk" ascii /* base64 encoded string 'IIIIII11l1='ftp_login';$IIIIIIII11ll='ftp_close';$IIIIIIII11lI='is_array';$IIIIIIII11I1='file';$' */
      $s2 = "b25fZGVzdHJveSc7JElJSUlJSUlsSWxJST0ndW5saW5rJzskSUlJSUlJSWxJSTExPSdiYXNlNjRfZGVjb2RlJzskSUlJSUlJSUkxMTFJPSdmdHBfY29ubmVjdCc7JElJ" ascii /* base64 encoded string 'on_destroy';$IIIIIIIlIlII='unlink';$IIIIIIIlII11='base64_decode';$IIIIIIII111I='ftp_connect';$II' */
      $s3 = "JElJSUlJSUlJMUlsbD0nY2VpbCc7JElJSUlJSUlJMUlJbD0nb2Jfc3RhcnQnOyRJSUlJSUlJSWwxMTE9J3Jlc2V0JzskSUlJSUlJSUlsMTFsPSdmb3Blbic7JElJSUlJ" ascii /* base64 encoded string '$IIIIIIII1Ill='ceil';$IIIIIIII1IIl='ob_start';$IIIIIIIIl111='reset';$IIIIIIIIl11l='fopen';$IIIII' */
      $s4 = "SUlJbDFsMT0naXNfbnVtZXJpYyc7JElJSUlJSUlJbGwxMT0nZndyaXRlJzskSUlJSUlJSUlsbGxJPSdpbXBsb2RlJzskSUlJSUlJSUlsbEkxPSdhZGRzbGFzaGVzJzsk" ascii /* base64 encoded string 'IIIl1l1='is_numeric';$IIIIIIIIll11='fwrite';$IIIIIIIIlllI='implode';$IIIIIIIIllI1='addslashes';$' */
      $s5 = "OyRJSUlJSUlJMUlJMTE9J3JlbmFtZSc7JElJSUlJSUkxSUkxbD0nYXJyYXlfbWFwJzskSUlJSUlJSTFJSWwxPSdyZWFscGF0aCc7JElJSUlJSUkxSUlsST0nZXNjYXBl" ascii /* base64 encoded string ';$IIIIIII1II11='rename';$IIIIIII1II1l='array_map';$IIIIIII1IIl1='realpath';$IIIIIII1IIlI='escape' */
      $s6 = "SUlJSUlJSTFJMWxJPSdmaWxlbXRpbWUnOyRJSUlJSUlJMUkxSUk9J2lzX2xpbmsnOyRJSUlJSUlJMUlsMTE9J2ZpbGVvd25lcic7JElJSUlJSUkxSWxsMT0ncmVhZGxp" ascii /* base64 encoded string 'IIIIIII1I1lI='filemtime';$IIIIIII1I1II='is_link';$IIIIIII1Il11='fileowner';$IIIIIII1Ill1='readli' */
      $s7 = "PSdhcnJheV91bmlxdWUnOyRJSUlJSUlsSWwxMWw9J3N0cnRvdXBwZXInOyRJSUlJSUlsSWwxbDE9J2luX2FycmF5JzskSUlJSUlJbElsMWxJPSdkZWNoZXgnOyRJSUlJ" ascii /* base64 encoded string '='array_unique';$IIIIIIlIl11l='strtoupper';$IIIIIIlIl1l1='in_array';$IIIIIIlIl1lI='dechex';$IIII' */
      $s8 = "JElJSUlJSWxJbGxsST0nZmx1c2gnOyRJSUlJSUlsSWxsSWw9J3JhbmQnOyRJSUlJSUlsSWxJbGw9J3JvdW5kJzskSUlJSUlJbElsSUlJPSdmc29ja29wZW4nOyRJSUlJ" ascii /* base64 encoded string '$IIIIIIlIlllI='flush';$IIIIIIlIllIl='rand';$IIIIIIlIlIll='round';$IIIIIIlIlIII='fsockopen';$IIII' */
      $s9 = "bGVncm91cCc7JElJSUlJSUlsMUkxMT0ncHJlZ19tYXRjaCc7JElJSUlJSUlsMUlJMT0nZmVvZic7JElJSUlJSUlsMUlJbD0nZXhlYyc7JElJSUlJSUlsMUlJST0ncGNs" ascii /* base64 encoded string 'legroup';$IIIIIIIl1I11='preg_match';$IIIIIIIl1II1='feof';$IIIIIIIl1IIl='exec';$IIIIIIIl1III='pcl' */
      $s10 = "bGUnOyRJSUlJSUlsSUlsSUk9J2ZpbGVhdGltZSc7JElJSUlJSWxJSUkxMT0nZmlsZWN0aW1lJzskSUlJSUlJbElJSWwxPSdpbmlfcmVzdG9yZSc7JElJSUlJSWxJSUls" ascii /* base64 encoded string 'le';$IIIIIIlIIlII='fileatime';$IIIIIIlIII11='filectime';$IIIIIIlIIIl1='ini_restore';$IIIIIIlIIIl' */
      $s11 = "bGltaXQnOyRJSUlJSUlJMWxsSUk9J2FkZGNzbGFzaGVzJzskSUlJSUlJSTFsSTExPSdpY29udic7JElJSUlJSUkxbElsMT0naXNfd3JpdGFibGUnOyRJSUlJSUlJMWxJ" ascii /* base64 encoded string 'limit';$IIIIIII1llII='addcslashes';$IIIIIII1lI11='iconv';$IIIIIII1lIl1='is_writable';$IIIIIII1lI' */
      $s12 = "c2hlbGxhcmcnOyRJSUlJSUlJMUlJSWw9J2lzX2ZpbGUnOyRJSUlJSUlJMUlJSUk9J2NvcHknOyRJSUlJSUlJbDExbGw9J2NoZGlyJzskSUlJSUlJSWwxMWxJPSdiYXNl" ascii /* base64 encoded string 'shellarg';$IIIIIII1IIIl='is_file';$IIIIIII1IIII='copy';$IIIIIIIl11ll='chdir';$IIIIIIIl11lI='base' */
      $s13 = "bmFtZSc7JElJSUlJSUlsMTFJMT0ncm1kaXInOyRJSUlJSUlJbDExSWw9J2Nsb3NlZGlyJzskSUlJSUlJSWwxMUlJPSdvcGVuZGlyJzskSUlJSUlJSWwxbDExPSdmaWxl" ascii /* base64 encoded string 'name';$IIIIIIIl11I1='rmdir';$IIIIIIIl11Il='closedir';$IIIIIIIl11II='opendir';$IIIIIIIl1l11='file' */
      $s14 = "SUlsSUkxMWw9J3N0cmlwc2xhc2hlcyc7JElJSUlJSWxJSTFJMT0nc3RydG90aW1lJzskSUlJSUlJbElJMUlsPSdvcmQnOyRJSUlJSUlsSUlsMTE9J3RvdWNoJzskSUlJ" ascii /* base64 encoded string 'IIlII11l='stripslashes';$IIIIIIlII1I1='strtotime';$IIIIIIlII1Il='ord';$IIIIIIlIIl11='touch';$III' */
      $s15 = "bGw9J2ZpbGVwZXJtcyc7JElJSUlJSUkxSTExMT0ncHJlZ19yZXBsYWNlJzskSUlJSUlJSTFJMWwxPSd1cmxlbmNvZGUnOyRJSUlJSUlJMUkxbGw9J2ZpbGVzaXplJzsk" ascii /* base64 encoded string 'll='fileperms';$IIIIIII1I111='preg_replace';$IIIIIII1I1l1='urlencode';$IIIIIII1I1ll='filesize';$' */
      $s16 = "SUlJbElJbDFJPSdwb3cnOyRJSUlJSUlsSUlsbDE9J2NsZWFyc3RhdGNhY2hlJzskSUlJSUlJbElJbGxJPSdjaG1vZCc7JElJSUlJSWxJSWxJMT0naGlnaGxpZ2h0X2Zp" ascii /* base64 encoded string 'IIIlIIl1I='pow';$IIIIIIlIIll1='clearstatcache';$IIIIIIlIIllI='chmod';$IIIIIIlIIlI1='highlight_fi' */
      $s17 = "eXN0ZW0nOyRJSUlJSUlJbGwxbGw9J3BvcGVuJzskSUlJSUlJSWxsMWxJPSdpc19yZXNvdXJjZSc7JElJSUlJSUlsbDFJMT0nZnJlYWQnOyRJSUlJSUlJbGwxSWw9J3No" ascii /* base64 encoded string 'ystem';$IIIIIIIll1ll='popen';$IIIIIIIll1lI='is_resource';$IIIIIIIll1I1='fread';$IIIIIIIll1Il='sh' */
      $s18 = "SUlJSUlJbEkxbEk9J3N0cnRvbG93ZXInOyRJSUlJSUlJbElsMTE9J2lzX3JlYWRhYmxlJzskSUlJSUlJSWxJbDFJPSdzdHJwb3MnOyRJSUlJSUlJbElsSTE9J3Nlc3Np" ascii /* base64 encoded string 'IIIIIIlI1lI='strtolower';$IIIIIIIlIl11='is_readable';$IIIIIIIlIl1I='strpos';$IIIIIIIlIlI1='sessi' */
      $s19 = "bD0nZ2xvYic7JElJSUlJSWxJSUlJMT0ndGVtcG5hbSc7JElJSUlJSUkxMUlJbD0ncmFuZ2UnOyRJSUlJSUlJMWwxMWw9J2dldG15Z2lkJzskSUlJSUlJSTFsMTFJPSdn" ascii /* base64 encoded string 'l='glob';$IIIIIIlIIII1='tempnam';$IIIIIII11IIl='range';$IIIIIII1l11l='getmygid';$IIIIIII1l11I='g' */
      $s20 = "b3NlJzskSUlJSUlJSWxsMTExPSdwYXNzdGhydSc7JElJSUlJSUlsbDExbD0nb2JfZ2V0X2NsZWFuJzskSUlJSUlJSWxsMTFJPSdqb2luJzskSUlJSUlJSWxsMWwxPSdz" ascii /* base64 encoded string 'ose';$IIIIIIIll111='passthru';$IIIIIIIll11l='ob_get_clean';$IIIIIIIll11I='join';$IIIIIIIll1l1='s' */
   condition:
      ( uint16(0) == 0x3f3c and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _securityghost_priv_Zero5eca1494b_2c16_412d_961c_a19841df04a5_jca2df63a45_6b2d_4d3c_897c_d4a9d9c8bd36_2 {
   meta:
      description = "php - from files securityghost-priv-Zero5eca1494b-2c16-412d-961c-a19841df04a5.php, jca2df63a45-6b2d-4d3c-897c-d4a9d9c8bd36.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "6cd9596d60669360cec589f005134372e85a7673917644e1d8b3a24554362da7"
      hash2 = "b3288f7b95cafd19e24ef63e840fdfba8760b0658503813c55b549f33f509457"
   strings:
      $s1 = "2v3Dp/rBseAprIcr2v3Dp/rBseAprIcr2v3Dp/rBseAprIcr2v3Dp/rBseAprIcr2v3Dp/rBseAprIcr2v3Dp/rBseAprIcr2v3Dp/rBseAprIcr2v3Dp/rBseApredQ" ascii
      $s2 = "2v3Dp/rBseAprIcr2v3Dp/rBseAprIcr2v3Dp/rBseAprIcr2v3Dp/rBseAprIcr2v3Dp/rBseAprIcr2v3Dp/rBseAprIcr2v3Dp/rBseAprIcr2v3Dp/rBseAprIcr" ascii
      $s3 = "X+GCsP/ysE2gWPfJsma5sP/lZ+fB6EikXmgJ6+f5sEiDYEi0ZPA5HlWtZqHJSMgNS8/hHEB56EfNXq7hs8khHliyX+SOZ+gBs8k5XNGfmNA5SIcTX+GCsP/ysE2gWPfJ" ascii
      $s4 = "sma5HocNZqfiS+A5HliNX+iPWNG5HocNZqfiS+A5HliNX+iPwmg5SIcTX+GtLbxOXq3DYEghWIHJXI7kwVQN6obCZ+7D6lgxXqfDSlWtZ+7D6lgxXqfDSvB5Xq3DYEgh" ascii
      $s5 = "SqfqHmWtZ+7D6lgB6ofvs+bOZ+gBs8k5XNGfmNA5SIcTX+GCsP/ysE2gWPiksIfD6obCZE/hWIBCHqQkSmadYV3yYofDHEGMwPiksIfD6obOZ+gBs8k5XNGfmNA5SIcT" ascii
      $s6 = "X+iPZ+JDsI3KZPf5XP6MwMgks8r5YIcDS8b56+ghHMgxsIcBHmiNX+iPwmg5SIcTX+GtLbxOZqfkX87NsLGCw8khSI7DWIciS82gW0fU6PUTsmWC6+AJSqrgWPkhSI7D" ascii
      $s7 = "wCD4w8gBs8k5XM3+6EAUHpDM6+/DWmgks8r5XP/dHEbh6+ghHMWtZ+7D6lgh6EUkHmiNX+iPwmg5SIcTX+GtLbxOXq3DYEghWIHJXI7kwVQN6obCZ+7D6lgxsIcBHmgN" ascii
      $s8 = "cD6B62f392" ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _pwsbddd94ac_c6ec_4503_b39e_450f53cf5853_php_reverse_shellddb3270c_f6ee_4546_bf15_f9597c6d0f86_k2ll33d23dc7bdb_be82_453a_bbb_3 {
   meta:
      description = "php - from files pwsbddd94ac-c6ec-4503-b39e-450f53cf5853.php, php-reverse-shellddb3270c-f6ee-4546-bf15-f9597c6d0f86.php, k2ll33d23dc7bdb-be82-453a-bbbc-5c89717eeb2b.php, rootshell735a8047-3184-40bd-a877-6751524be103.php, qsd-php-backdoor1b5d7012-9e7a-47a1-a650-491a3c157e4e.php, ru24_post_sh6578d94a-12ec-45f9-b245-f1deabb3fea7.php, php-include-w-shella43eb8ec-15e7-42a4-9fdb-04d5a25c6d9b.php, Ayyildiz Tim Shell (Private Shell 2017)dfa28735-06a3-4725-b6ac-df08f0e87961.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "391e93938a94b269d99977fff13467d2e8af671e01ec550451bb8cc01b1cdd4e"
      hash2 = "fcae04366800010ff37e7cf42f0292ff0ecdeaac6248f30c8fe24414f00ec62f"
      hash3 = "d45af3a7336fe8e73ee61543fd3022c542e3256baa77554fc198f7dfcf143067"
      hash4 = "01fe394bd94415925a825738bb143e27ea820321cbc52c47e1c38d9b311b16e7"
      hash5 = "f4ff97672147876440a96e01c6d0cb3ef2dd73de065bcbd031158143b00eae77"
      hash6 = "b855e7862668d0092c26fe045e8b39706ce3e513c6984c3f5322c0cc7020ff3e"
      hash7 = "b2c422aeb5f2237a941cfd75e21178116d25403a67914f1141e6e40dbcf0ec64"
      hash8 = "f85c118000110a08056a95840a244610ad3c13d5edb0b9278aa7cb9d327e782f"
   strings:
      $s1 = "<?php /* Reverse engineering of this file is strictly prohibited. File protected by copyright law and provided under license. */" ascii
      $s2 = "($ekV4gb3DGH29YotI[$rZJ3glaFcSAz0dZY+1])-ord('A'))*16+(ord($ekV4gb3DGH29YotI[$rZJ3glaFcSAz0dZY+2])-ord('a'))); $rZJ3glaFcSAz0dZY" ascii
      $s3 = "cSAz0dZY] == ' ') { $fYZ2g87NjIGLnXVg.=\" \"; } else if($ekV4gb3DGH29YotI[$rZJ3glaFcSAz0dZY] == '!') { $fYZ2g87NjIGLnXVg.=chr((o" ascii
      $s4 = "+=2; } else { $fYZ2g87NjIGLnXVg.=chr(ord($ekV4gb3DGH29YotI[$rZJ3glaFcSAz0dZY])+1); } $rZJ3glaFcSAz0dZY++; } return $fYZ2g87NjIGL" ascii
      $s5 = "ZY=0; $qVh0gqGnK20A4iOB=strlen($ekV4gb3DGH29YotI); while($rZJ3glaFcSAz0dZY < $qVh0gqGnK20A4iOB) { if($ekV4gb3DGH29YotI[$rZJ3glaF" ascii
      $s6 = " if(!function_exists(\"agF1gTdKEBPd6CaJ\")) { function agF1gTdKEBPd6CaJ($ekV4gb3DGH29YotI) { $fYZ2g87NjIGLnXVg=\"\"; $rZJ3glaFcS" ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 1000KB and ( all of them )
      ) or ( all of them )
}

rule _hector_uploader3efd02fe_1e7b_4fa2_a494_1f8e505e1eb2_nobody_uploader75ccbc89_d53f_4273_89e2_99cf7ab48a01_4 {
   meta:
      description = "php - from files hector-uploader3efd02fe-1e7b-4fa2-a494-1f8e505e1eb2.php, nobody-uploader75ccbc89-d53f-4273-89e2-99cf7ab48a01.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "e694b3ba6150a49fd588f76fda0c872ac43e383967623411283ac93ed9a2ac0a"
      hash2 = "2ff89778dded2a5a2d38b28b8f1f6e23bb9f70be562d2c089af757daae3d0548"
   strings:
      $s1 = "yZjl3YmNWcDI3RW82SFlYU3N1akNKTU5La1AweFRSMXlkaDVCQWx2RFUrcUdpRm5PZ3R6PScsJ0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5" ascii /* base64 encoded string 'f9wbcVp27Eo6HYXSsujCJMNKkP0xTR1ydh5BAlvDU+qGiFnOgtz=','ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn' */
      $s2 = "SUlJSUlJSUlsMT0ndG91Y2gnOyRJSUlJSUlJSUlJbGw9J3RpbWUnOyRJSUlJSUlJSUlJSUk9J2lzX3VwbG9hZGVkX2ZpbGUnOw==')); ?><?php /* xorro@jabber" ascii
      $s3 = "{11}.$OOO000000{12}.$OOO0000O0{7}.$OOO000000{5};?><?php eval($GLOBALS['OOO0000O0']('JElJSUlJSUlJSUkxbD0nYmFzZTY0X2RlY29kZSc7JElJ" ascii
      $s4 = ".ru */$OOO000O00=$OOO000000{0}.$OOO000000{12}.$OOO000000{7}.$OOO000000{5}.$OOO000000{15};$O0O000O00=$OOO000000{0}.$OOO000000{1}." ascii
      $s5 = "$OOO000000{5}.$OOO000000{14};$O0O000O0O=$O0O000O00.$OOO000000{11};$O0O000O00=$O0O000O00.$OOO000000{3};$O0O00OO00=$OOO000000{0}.$" ascii
      $s6 = "OOO000000{8}.$OOO000000{5}.$OOO000000{9}.$OOO000000{16};$OOO00000O=$OOO000000{3}.$OOO000000{14}.$OOO000000{8}.$OOO000000{14}.$OO" ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 10KB and ( all of them )
      ) or ( all of them )
}

rule _bypass403bc2cc0f9_5443_44d2_9261_153a3cd72e01_safe0ver313ba731_25f0_44db_8477_032a89e27e44_5 {
   meta:
      description = "php - from files bypass403bc2cc0f9-5443-44d2-9261-153a3cd72e01.php, safe0ver313ba731-25f0-44db-8477-032a89e27e44.php"
      author = "dosec"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-22"
      hash1 = "2e94593ca67d7710be39c1d2ef1d0636068ec5ec4ce38f3fce5dd1c5ed12f15e"
      hash2 = "0b17d2030491bc4822448a070a5c5506a38e2321f3ef83ba0b88656af1e08e61"
   strings:
      $s1 = "5La1AweFRSMXlkaDVCQWx2RFUrcUdpRm5PZ3R6PScsJ0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5Ky" ascii
      $s2 = "8wME8wME8wPSRPT08wMDAwTzAoJE9PTzAwMDAwTygkTzBPMDBPTzAwKCRPMDAwTzBPMDAsMHgxN2MpLCdhM21MZS84SVdRNFpyZjl3YmNWcDI3RW82SFlYU3N1akNKTU" ascii
      $s3 = "00000{9}.$OOO000000{16};$OOO00000O=$OOO000000{3}.$OOO000000{14}.$OOO000000{8}.$OOO000000{14}.$OOO000000{8};$OOO0O0O00=__FILE__;$" ascii
      $s4 = "OOO000000{12}.$OOO000000{7}.$OOO000000{5}.$OOO000000{15};$O0O000O00=$OOO000000{0}.$OOO000000{1}.$OOO000000{5}.$OOO000000{14};$O0" ascii
      $s5 = "O000O0O=$O0O000O00.$OOO000000{11};$O0O000O00=$O0O000O00.$OOO000000{3};$O0O00OO00=$OOO000000{0}.$OOO000000{8}.$OOO000000{5}.$OOO0" ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 100KB and ( all of them )
      ) or ( all of them )
}

