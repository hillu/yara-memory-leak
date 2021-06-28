/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2021-06-18
   Identifier: php
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _home_skrbug_go_src_dosec_cn_webshell_sample_sp_webshell_BehinderSort_php_shell_9 {
   meta:
      description = "php - file shell_9.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-18"
      hash1 = "f5bf5fe917b293f5e5905b9dd7f5a2c27e1743fd700a4722ed5641d00394a701"
   strings:
      $s1 = "$post=file_get_contents(\"php://input\");"  ascii /* score: '14.00'*/
      $s2 = "$post=openssl_decrypt($post, \"AES128\", $key);"  ascii /* score: '14.00'*/
      $s3 = "if (isset($_GET['pass']))"  ascii /* score: '12.00'*/
      $s4 = " $post[$i] = $post[$i]^$key[$i+1&15]; "  ascii /* score: '12.00'*/
      $s5 = "@error_reporting(0);"  ascii /* score: '10.00'*/
      $s6 = "for($i=0;$i<strlen($post);$i++) {"  ascii /* score: '9.00'*/
      $s7 = "$post=$t($post.\"\");"  ascii /* score: '9.00'*/
      $s8 = "$t=\"base64_\".\"decode\";"  ascii /* score: '6.00'*/
      $s9 = "    $key=$_SESSION['k'];"  ascii /* score: '5.00'*/
      $s10 = "    $_SESSION['k']=$key;"  ascii /* score: '5.00'*/
      $s11 = "@new C($params);"  ascii /* score: '4.00'*/
      $s12 = "    $arr=explode('|',$post);"  ascii /* score: '4.00'*/
      $s13 = "if(!extension_loaded('openssl'))"  ascii /* score: '4.00'*/
      $s14 = "class C{public function __construct($p) {eval($p.\"\");}}"  ascii /* score: '3.00'*/
      $s15 = "    print $key;"  ascii /* score: '2.00'*/
      $s16 = "    $key=substr(md5(uniqid(rand())),16);"  ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      8 of them
}

rule _home_skrbug_go_src_dosec_cn_webshell_sample_sp_webshell_BehinderSort_php_shell_8 {
   meta:
      description = "php - file shell_8.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-18"
      hash1 = "756934f30ca23757fc348cbb0080c8846ae6004a509a2be8125851f7f042a9cd"
   strings:
      $s1 = "$post=file_get_contents(\"php://input\");"  ascii /* score: '14.00'*/
      $s2 = "$post=openssl_decrypt($post, \"AES128\", $key);"  ascii /* score: '14.00'*/
      $s3 = "if (isset($_GET['pass']))"  ascii /* score: '12.00'*/
      $s4 = " $post[$i] = $post[$i]^$key[$i+1&15]; "  ascii /* score: '12.00'*/
      $s5 = "@error_reporting(0);"  ascii /* score: '10.00'*/
      $s6 = "for($i=0;$i<strlen($post);$i++) {"  ascii /* score: '9.00'*/
      $s7 = "$post=$t($post.\"\");"  ascii /* score: '9.00'*/
      $s8 = "$t=\"base64_\".\"decode\";"  ascii /* score: '6.00'*/
      $s9 = "    $key=$_SESSION['k'];"  ascii /* score: '5.00'*/
      $s10 = "    $_SESSION['k']=$key;"  ascii /* score: '5.00'*/
      $s11 = "    $arr=explode('|',$post);"  ascii /* score: '4.00'*/
      $s12 = "if(!extension_loaded('openssl'))"  ascii /* score: '4.00'*/
      $s13 = "class C{public function __invoke($p) {eval($p.\"\");}}"  ascii /* score: '3.00'*/
      $s14 = "    print $key;"  ascii /* score: '2.00'*/
      $s15 = "    $key=substr(md5(uniqid(rand())),16);"  ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      8 of them
}

rule shell_18 {
   meta:
      description = "php - file shell_18.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-18"
      hash1 = "3cf81eba189cdedde93a9f4fbbb85bed58dbfade1bc7a81656c205957a7de677"
   strings:
      $s1 = "$post=file_get_contents(\"php://input\");"  ascii /* score: '14.00'*/
      $s2 = "$post=openssl_decrypt($post, \"AES128\", $key);"  ascii /* score: '14.00'*/
      $s3 = " $post[$i] = $post[$i]^$key[$i+1&15]; "  ascii /* score: '12.00'*/
      $s4 = "@error_reporting(0);"  ascii /* score: '10.00'*/
      $s5 = "$_SESSION['k']=$key;"  ascii /* score: '10.00'*/
      $s6 = "for($i=0;$i<strlen($post);$i++) {"  ascii /* score: '9.00'*/
      $s7 = "$post=$t($post.\"\");"  ascii /* score: '9.00'*/
      $s8 = "rebeyond"  ascii /* score: '8.00'*/
      $s9 = "$t=\"base64_\".\"decode\";"  ascii /* score: '6.00'*/
      $s10 = "    $arr=explode('|',$post);"  ascii /* score: '4.00'*/
      $s11 = "if(!extension_loaded('openssl'))"  ascii /* score: '4.00'*/
      $s12 = "class C{public function __invoke($p) {eval($p.\"\");}}"  ascii /* score: '3.00'*/
      $s13 = "e45e329feb5d925b" ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      8 of them
}

rule shell_13 {
   meta:
      description = "php - file shell_13.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-18"
      hash1 = "8cc698fe9018b617b7a5e442e5e2c2d7bb015ef39a02908d55976bb8e45991db"
   strings:
      $s1 = "$post=file_get_contents(\"php://input\");"  ascii /* score: '14.00'*/
      $s2 = "$post=openssl_decrypt($post, \"AES128\", $key);"  ascii /* score: '14.00'*/
      $s3 = " $post[$i] = $post[$i]^$key[$i+1&15]; "  ascii /* score: '12.00'*/
      $s4 = "@error_reporting(0);"  ascii /* score: '10.00'*/
      $s5 = "$_SESSION['k']=$key;"  ascii /* score: '10.00'*/
      $s6 = "for($i=0;$i<strlen($post);$i++) {"  ascii /* score: '9.00'*/
      $s7 = "$post=$t($post.\"\");"  ascii /* score: '9.00'*/
      $s8 = "if ($_SERVER['REQUEST_METHOD'] === 'POST')"  ascii /* score: '9.00'*/
      $s9 = "$t=\"base64_\".\"decode\";"  ascii /* score: '6.00'*/
      $s10 = "    $arr=explode('|',$post);"  ascii /* score: '4.00'*/
      $s11 = "if(!extension_loaded('openssl'))"  ascii /* score: '4.00'*/
      $s12 = "class C{public function __invoke($p) {eval($p.\"\");}}"  ascii /* score: '3.00'*/
      $s13 = "e45e329feb5d925b" ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      8 of them
}

rule shell_21 {
   meta:
      description = "php - file shell_21.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-18"
      hash1 = "9a94483a4563228cb698173c1991c7cf90726c2c126a3ce74c66ba226040f760"
   strings:
      $s1 = "$post=file_get_contents(\"php://input\");"  ascii /* score: '14.00'*/
      $s2 = "$post=openssl_decrypt($post, \"AES128\", $key);"  ascii /* score: '14.00'*/
      $s3 = " $post[$i] = $post[$i]^$key[$i+1&15]; "  ascii /* score: '12.00'*/
      $s4 = "@error_reporting(0);"  ascii /* score: '10.00'*/
      $s5 = "$_SESSION['k']=$key;"  ascii /* score: '10.00'*/
      $s6 = "for($i=0;$i<strlen($post);$i++) {"  ascii /* score: '9.00'*/
      $s7 = "$post=$t($post.\"\");"  ascii /* score: '9.00'*/
      $s8 = "rebeyond"  ascii /* score: '8.00'*/
      $s9 = "$t=\"base64_\".\"decode\";"  ascii /* score: '6.00'*/
      $s10 = "    $arr=explode('|',$post);"  ascii /* score: '4.00'*/
      $s11 = "if(!extension_loaded('openssl'))"  ascii /* score: '4.00'*/
      $s12 = "class C{public function __invoke($p) {eval($p.\"\");}}"  ascii /* score: '3.00'*/
      $s13 = "e45e329feb5d925b" ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      8 of them
}

rule _home_skrbug_go_src_dosec_cn_webshell_sample_sp_webshell_BehinderSort_php_shell_5 {
   meta:
      description = "php - file shell_5.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-18"
      hash1 = "99ac30084924ad81051626695f86ecfea13240f935c9cd814a3b2564ce213973"
   strings:
      $s1 = "<?php session_start();isset($_GET['pass'])?print $_SESSION['k']=substr(md5(uniqid(rand())),16):($b=explode('|',openssl_decrypt(f" ascii /* score: '15.00'*/
      $s2 = "<?php session_start();isset($_GET['pass'])?print $_SESSION['k']=substr(md5(uniqid(rand())),16):($b=explode('|',openssl_decrypt(f" ascii /* score: '14.00'*/
      $s3 = "ile_get_contents(\"php://input\"), \"AES128\", $_SESSION['k'])))&@call_user_func($b[0],$b[1]);?>"  ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule _home_skrbug_go_src_dosec_cn_webshell_sample_sp_webshell_BehinderSort_php_shell_6 {
   meta:
      description = "php - file shell_6.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-18"
      hash1 = "0c0ab951fce61160f2766aca66cc98b8a30ca588785bec8c48a8214c8ae376ac"
   strings:
      $s1 = "<?php class C{public function __invoke($p) {eval($p.\"\");}};session_start();isset($_GET['pass'])?print $_SESSION['k']=substr(md" ascii /* score: '18.00'*/
      $s2 = "uniqid(rand())),16):($b=explode('|',openssl_decrypt(file_get_contents(\"php://input\"), \"AES128\", $_SESSION['k'])))&@call_user" ascii /* score: '15.00'*/
      $s3 = "<?php class C{public function __invoke($p) {eval($p.\"\");}};session_start();isset($_GET['pass'])?print $_SESSION['k']=substr(md" ascii /* score: '11.00'*/
      $s4 = "c(new C(),$b[1]);?>"  ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _shell_9_shell_8_shell_18_shell_13_shell_21_0 {
   meta:
      description = "php - from files shell_9.php, shell_8.php, shell_18.php, shell_13.php, shell_21.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-18"
      hash1 = "f5bf5fe917b293f5e5905b9dd7f5a2c27e1743fd700a4722ed5641d00394a701"
      hash2 = "756934f30ca23757fc348cbb0080c8846ae6004a509a2be8125851f7f042a9cd"
      hash3 = "3cf81eba189cdedde93a9f4fbbb85bed58dbfade1bc7a81656c205957a7de677"
      hash4 = "8cc698fe9018b617b7a5e442e5e2c2d7bb015ef39a02908d55976bb8e45991db"
      hash5 = "9a94483a4563228cb698173c1991c7cf90726c2c126a3ce74c66ba226040f760"
   strings:
      $s1 = "$post=file_get_contents(\"php://input\");"  ascii /* score: '14.00'*/
      $s2 = "$post=openssl_decrypt($post, \"AES128\", $key);"  ascii /* score: '14.00'*/
      $s3 = " $post[$i] = $post[$i]^$key[$i+1&15]; "  ascii /* score: '12.00'*/
      $s4 = "@error_reporting(0);"  ascii /* score: '10.00'*/
      $s5 = "for($i=0;$i<strlen($post);$i++) {"  ascii /* score: '9.00'*/
      $s6 = "$post=$t($post.\"\");"  ascii /* score: '9.00'*/
      $s7 = "$t=\"base64_\".\"decode\";"  ascii /* score: '6.00'*/
      $s8 = "    $arr=explode('|',$post);"  ascii /* score: '4.00'*/
      $s9 = "if(!extension_loaded('openssl'))"  ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 1KB and ( all of them )
      ) or ( all of them )
}

rule _shell_9_shell_8_1 {
   meta:
      description = "php - from files shell_9.php, shell_8.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-06-18"
      hash1 = "f5bf5fe917b293f5e5905b9dd7f5a2c27e1743fd700a4722ed5641d00394a701"
      hash2 = "756934f30ca23757fc348cbb0080c8846ae6004a509a2be8125851f7f042a9cd"
   strings:
      $s1 = "if (isset($_GET['pass']))"  ascii /* score: '12.00'*/
      $s2 = "    $key=$_SESSION['k'];"  ascii /* score: '5.00'*/
      $s3 = "    $_SESSION['k']=$key;"  ascii /* score: '5.00'*/
      $s4 = "    print $key;"  ascii /* score: '2.00'*/
      $s5 = "    $key=substr(md5(uniqid(rand())),16);"  ascii /* score: '2.00'*/
   condition:
      ( uint16(0) == 0x3f3c and filesize < 1KB and ( all of them )
      ) or ( all of them )
}

