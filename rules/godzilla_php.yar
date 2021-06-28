/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2021-06-17
   Identifier: php
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule PHP_EVAL_XOR_BASE64_7 {
   meta:
      description = "php - file PHP_EVAL_XOR_BASE64_7.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-17"
      hash1 = "6b157f60c598ee68bc8958e19755bc2786166c3f6aef37a15b77f4ce7aeb5a11"
   strings:
      $s1 = "eval($_POST[\"pass\"]);" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule PHP_XOR_BASE64_8 {
   meta:
      description = "php - file PHP_XOR_BASE64_8.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-17"
      hash1 = "4c1de7123c4d48c0d671b3d3c4e60da668c697285a7639ec01334fb3f527de49"
   strings:
      $s1 = "            $_SESSION[$payloadName]=encode($data,$key);" fullword ascii
      $s2 = "        $payload=encode($_SESSION[$payloadName],$key);" fullword ascii
      $s3 = "$payloadName='payload';" fullword ascii
      $s4 = "if (isset($_POST[$pass])){" fullword ascii
      $s5 = "    $data=encode(base64_decode($_POST[$pass]),$key);" fullword ascii
      $s6 = "    if (isset($_SESSION[$payloadName])){" fullword ascii
      $s7 = "@error_reporting(0);" fullword ascii
      $s8 = "        eval($payload);" fullword ascii
      $s9 = "$pass='pass';" fullword ascii
      $s10 = "        }" fullword ascii /* reversed goodware string '}        ' */
      $s11 = "        echo substr(md5($pass.$key),0,16);" fullword ascii
      $s12 = "        echo substr(md5($pass.$key),16);" fullword ascii
      $s13 = "        echo base64_encode(encode(@run($data),$key));" fullword ascii
      $s14 = "function encode($D,$K){" fullword ascii
      $s15 = "$key='3c6e0b8a9c15224a';" fullword ascii
      $s16 = "        if (stripos($data,\"getBasicsInfo\")!==false){" fullword ascii
      $s17 = "@session_start();" fullword ascii /* Goodware String - occured 3 times */
      $s18 = "3c6e0b8a9c15224a" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 2KB and
      8 of them
}

rule PHP_XOR_RAW_9 {
   meta:
      description = "php - file PHP_XOR_RAW_9.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-17"
      hash1 = "b8fd450e16610f3cc307e7b1b3309ad4e79456860ec16dec1006250b8afe49b2"
   strings:
      $s1 = "            $_SESSION[$payloadName]=encode($data,$key);" fullword ascii
      $s2 = "        $payload=encode($_SESSION[$payloadName],$key);" fullword ascii
      $s3 = "$data=file_get_contents(\"php://input\");" fullword ascii
      $s4 = "$payloadName='payload';" fullword ascii
      $s5 = "eval($payload);" fullword ascii
      $s6 = "    if (isset($_SESSION[$payloadName])){" fullword ascii
      $s7 = "@error_reporting(0);" fullword ascii
      $s8 = "        }" fullword ascii /* reversed goodware string '}        ' */
      $s9 = "        echo encode(@run($data),$key);" fullword ascii
      $s10 = "function encode($D,$K){" fullword ascii
      $s11 = "$key='3c6e0b8a9c15224a';" fullword ascii
      $s12 = "        if (stripos($data,\"getBasicsInfo\")!==false){" fullword ascii
      $s13 = "if ($data!==false){" fullword ascii
      $s14 = "@session_start();" fullword ascii /* Goodware String - occured 3 times */
      $s15 = "    $data=encode($data,$key);" fullword ascii
      $s16 = "3c6e0b8a9c15224a" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _PHP_XOR_BASE64_8_PHP_XOR_RAW_9_0 {
   meta:
      description = "php - from files PHP_XOR_BASE64_8.php, PHP_XOR_RAW_9.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-17"
      hash1 = "4c1de7123c4d48c0d671b3d3c4e60da668c697285a7639ec01334fb3f527de49"
      hash2 = "b8fd450e16610f3cc307e7b1b3309ad4e79456860ec16dec1006250b8afe49b2"
   strings:
      $s1 = "            $_SESSION[$payloadName]=encode($data,$key);" fullword ascii
      $s2 = "        $payload=encode($_SESSION[$payloadName],$key);" fullword ascii
      $s3 = "$payloadName='payload';" fullword ascii
      $s4 = "    if (isset($_SESSION[$payloadName])){" fullword ascii
      $s5 = "@error_reporting(0);" fullword ascii
      $s6 = "        }" fullword ascii /* reversed goodware string '}        ' */
      $s7 = "function encode($D,$K){" fullword ascii
      $s8 = "$key='3c6e0b8a9c15224a';" fullword ascii
      $s9 = "        if (stripos($data,\"getBasicsInfo\")!==false){" fullword ascii
      $s10 = "@session_start();" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "3c6e0b8a9c15224a" ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 2KB and ( 8 of them )
      ) or ( all of them )
}

