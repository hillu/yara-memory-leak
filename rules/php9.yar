/*
   YARA Rule Set
   Author: WatcherLab
   Date: 2019-01-02
   Identifier: php
*/

/* Rule Set ----------------------------------------------------------------- */
























rule php_MyShell {
   meta:
      description = "php - file MyShell.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "5d13d1806210953c3a728da9fa75ab82f31ea61cc09519ba668cc13708b33a82"
   strings:
      $x1 = "if($ok==false &&$status && $autoErrorTrap)system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/output.t" fullword ascii
      $s2 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/output.txt\");" fullword ascii
      $s3 = "#Bear in mind that MyShell executes the command again in order to" fullword ascii
      $s4 = "An interactive PHP-page that will execute any command entered." fullword ascii
      $s5 = "echo \"<a href=\\\"$PHP_SELF?work_dir=\" . urlencode($url) . \"/&command=\" . urlencode($command) . \"\\\">Root</a>/\";" fullword ascii
      $s6 = "mail($adminEmail,\"MyShell Warning - Unauthorized Access\",$warnMsg," fullword ascii
      $s7 = "#$autoErrorTrap Enable automatic error traping if command returns error." fullword ascii
      $s8 = "#to any address you want i.e.: noreplay@yourdomain.com" fullword ascii
      $s9 = "shell.command.select()>" fullword ascii
      $s10 = "&nbsp; | &nbsp;<input type=\"checkbox\" name=\"echoCommand\"<?if($echoCommand)echo \" checked\"?>>Echo commands" fullword ascii
      $s11 = "<title>MyShell error - Access Denied</title>" fullword ascii
      $s12 = "&nbsp;| ::::::::::&nbsp;<a href=\"http://www.digitart.net\" target=\"_blank\" style=\"text-decoration:none\"><b>MyShell</b> &cop" ascii
      $s13 = "if($ok==false &&$status && $autoErrorTrap)system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/output.txt" ascii
      $s14 = "#and set up your user and password using $shellUser and $shellPswd." fullword ascii
      $s15 = "&nbsp;| ::::::::::&nbsp;<a href=\"http://www.digitart.net\" target=\"_blank\" style=\"text-decoration:none\"><b>MyShell</b> &cop" ascii
      $s16 = "User Agent: \".$HTTP_SERVER_VARS[\"HTTP_USER_AGENT\"].\"" fullword ascii
      $s17 = "$Id: shell.php,v 1.0.5 2001/09/08 09:28:42 digitart Exp $" fullword ascii
      $s18 = "exec($command,$man);" fullword ascii
      $s19 = "#someone tries to access the script and fails to provide correct user and" fullword ascii
      $s20 = "#i.e.: mkdir /tmp/mydir or cat /home/otheruser/.htaccess." fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 30KB and
      1 of ($x*) and 4 of them
}



rule KA_uShell_0_1_6 {
   meta:
      description = "php - file KA_uShell 0.1.6.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "06d8c97448db0b9c7790e0d94fcb8db79162ea23ac65f1f74e687f3186017f73"
   strings:
      $s1 = "if (empty($_POST['wser'])) {$wser = \"whois.ripe.net\";} else $wser = $_POST['wser'];" fullword ascii
      $s2 = "header('WWW-Authenticate: Basic realm=\"KA_uShell\"');" fullword ascii
      $s3 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}" fullword ascii
      $s4 = "header('HTTP/1.0 401 Unauthorized');" fullword ascii
      $s5 = "//PHP Eval Code execution" fullword ascii
      $s6 = "$login = \"admin\";" fullword ascii
      $s7 = "$uploadfile = $_POST['path'].$_FILES['file']['name'];" fullword ascii
      $s8 = "<form enctype=\"multipart/form-data\" action=\"$self\" method=\"POST\">" fullword ascii
      $s9 = "$$sern <input size=\"50\" type=\"text\" name=\"c\"><input align=\"right\" type=\"submit\" value=\"Enter\">" fullword ascii
      $s10 = "<td><input size=\"40\" type=\"text\" name=\"wser\" value=\"whois.ripe.net\"></td>" fullword ascii
      $s11 = "ER']<>$login)" fullword ascii
      $s12 = ":<b>\" .base64_decode($_POST['tot']). \"</b>\";" fullword ascii
      $s13 = "<td><input size=\"48\" value=\"$docr/\" name=\"path\" type=\"text\"><input type=\"submit\" value=\"" fullword ascii
      $s14 = "if (copy($_FILES['file']['tmp_name'], $uploadfile)) {" fullword ascii
      $s15 = "if (isset($_POST['wq']) && $_POST['wq']<>\"\") {" fullword ascii
      $s16 = "if (!empty($_POST['tot']) && !empty($_POST['tac'])) {" fullword ascii
      $s17 = "elseif (!empty($_POST['ac'])) {$ac = $_POST['ac'];}" fullword ascii
      $s18 = "<input type=\"hidden\" name=\"ac\" value=\"shell\">" fullword ascii
      $s19 = "if(empty($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW']<>$pass || empty($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_US" ascii
      $s20 = "passthru($_POST['c']);" fullword ascii
   condition:
      uint16(0) == 0x213c and filesize < 10KB and
      8 of them
}



/* Super Rules ------------------------------------------------------------- */

rule _DxShell_v1_0_DxShell_1_0_0 {
   meta:
      description = "php - from files DxShell v1.0.txt, DxShell.1.0.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "23d2a555aea81b89893a2f4ae642c289174c5a31fd763120a1251b6e492e565e"
      hash2 = "c54ef6498b338df0cd2809657c6eea9972f6d7c4697fb1d4e0891eef62b4bca2"
   strings:
      $x1 = "$DEF_PORTS=array (1=>'tcpmux (TCP Port Service Multiplexer)',2=>'Management Utility',3=>'Compression Process',5=>'rje (Remote Jo" ascii
      $x2 = "$DxDOWNLOAD_File['content'].=\"\\n\\t\".'==== MySQL Dump '.DxDate(time()).' - DxShell v'.$GLOB['SHELL']['Ver'].' by o_O Tync';" fullword ascii
      $x3 = "foreach ($DUMP[0] as $key => $val) $DxDOWNLOAD_File['content'].=$key.\";\"; /* headers */" fullword ascii
      $x4 = "$DxDOWNLOAD_File['filename']='Dump_'.$_GET['dxsql_s'].'_'.$_GET['dxsql_d'].'.sql';" fullword ascii
      $x5 = "print \"\\n\\t\".'<input type=text name=\"DxFTP_FTP\" value=\"ftp.host.com[:21]\" style=\"width:100%;\">';" fullword ascii
      $x6 = "function DxExecNahuj($cmd, &$OUT, &$RET) /* returns the name of function that exists, or FALSE */" fullword ascii
      $x7 = "Url'])?$_POST['DxProx_Url']:'http://www.microsoft.com:80/index.php?get=q&get2=d').'\" style=\"width:100%;\"></td></tr>';" fullword ascii
      $x8 = "((@$_POST['DxS_Auth']['L']==$GLOB['SHELL']['USER']['Login']) AND /* form */" fullword ascii
      $x9 = "function DxHTTPMakeHeaders($method='', $URL='', $host='', $user_agent='', $referer='', $posts=array(), $cookie=array())" fullword ascii
      $x10 = "if (!ftp_login($FTP, $_POST['DxFTP_USER'], $_POST['DxFTP_PASS'])) die(DxError('Login failed'));" fullword ascii
      $x11 = "@$_COOKIE['DxS_AuthC']==md5($GLOB['SHELL']['USER']['Login'].$GLOB['SHELL']['USER']['Passw']) /* cookie */" fullword ascii
      $x12 = "$DxDOWNLOAD_File['headers'][]=('Content-type: text/plain'); /* usual look thru */" fullword ascii
      $x13 = "$DxDOWNLOAD_File['headers'][]=('Content-disposition: attachment; filename=\"'.$DxDOWNLOAD_File['filename'].'\";');" fullword ascii
      $x14 = "$DxDOWNLOAD_File['content'].=\"\\n\".'INSERT INTO `'.$CUR_TABLE.'` VALUES (\"'.implode('\", \"', $DUMP[$i]).'\");';" fullword ascii
      $x15 = "host'])?$_POST['dxsock_host']:'www.microsoft.com') ).'\" style=\"width:100%;\">';" fullword ascii
      $x16 = "T['DxMailer_TO']))?'tristam@mail.ru'.\"\\n\".'billy@microsoft.com':$_POST['DxMailer_TO']  ).'</textarea></td></tr>';" fullword ascii
      $x17 = "$DxDOWNLOAD_File['headers'][]=('Content-disposition: attachment; filename=\"'.basename($_GET['dxfile']).'\";');" fullword ascii
      $s18 = "document.getElementById(\"LolBox\").value = contents + tl[index].substring(0,text_pos)+'|';" fullword ascii
      $s19 = "$DxDOWNLOAD_File['headers'][]=('Content-type: text/comma-separated-values');" fullword ascii
      $s20 = "r_FROM']))?'DxS <admin@'.$_SERVER['HTTP_HOST']:$_POST['DxMailer_FROM']  ).'>\" style=\"width:100%;\"></td></tr>';" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 300KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _NetworkFileManagerPHP_NFM_1_8_1 {
   meta:
      description = "php - from files NetworkFileManagerPHP.txt, NFM 1.8.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "0863907cbabc1679e00a99f84c5adc3ff4daab11aa0df970e37f051c770d31ed"
      hash2 = "c9a73b6128994707f4cce41ac8c80bf522cab11e413871718607b8e1bfa4683c"
   strings:
      $x1 = "fputs($f,\"Enter on ftp:\\nFTPhosting:\\t$host\\nLogin:\\t$login\\nPassword:\\t$password\\n \");" fullword ascii
      $x2 = "else { open_file(\"dump_\".$dte.$tbl[$i].$fc.\".sql\".$gz);write_file($temp.\"\\n\\n\");close_file();$nbf=1; }" fullword ascii
      $x3 = "t=black bordercolordark=white><tr><td align=center>\".$g[1].\":\".$g[1].\" - <b>failed</b></td></tr></table>\";" fullword ascii
      $x4 = "global $action,$private_site, $title_exp,$login, $host, $file, $chislo, $proverka;" fullword ascii
      $s5 = "global $status,$form,$action,$name,$email,$pole,$REMOTE_ADDR,$HTTP_REFERER,$DOCUMENT_ROOT,$PATH_TRANSLATED,$HTTP_HOST;" fullword ascii
      $s6 = "else { close_file(); $nbf++; open_file(\"dump_\".$dte.$tbl[$i].$fc.\"_\".$nbf.\".sql\".$gz); write_file($val.\";\"); }" fullword ascii
      $s7 = "global $action,$status, $file3,$file2,$tm,$PHP_SELF,$HTTP_HOST,$style_button, $public_site, $private_site, $private, $public, $" fullword ascii
      $s8 = "<td valign=top><input type=text name=cm size=90 class='inputbox'value='tar -zc /home/$name$http_public -f $name.tar.gz' ></td>" fullword ascii
      $s9 = "ht=black bordercolordark=white><tr><td align=center class=pagetitle><b>Connected with login:password - \".$g[1].\":\".$g[1].\"</" ascii
      $s10 = "echo \"<TABLE CELLPADDING=0 CELLSPACING=0 bgcolor=#184984 BORDER=1 width=600 align=center bordercolor=#808080 bordercolorlight=b" ascii
      $s11 = "$private[2] = \"dupescan\"; // Glftpd DupeScan Local Exploit by RagnaroK" fullword ascii
      $s12 = "echo $header.\"<script language='javascript'> function checkall() { var i=0;while (i < $nb_tbl) { a='tbls['+i+']';document.form" fullword ascii
      $s13 = "global $action,$status, $tm,$PHP_SELF,$HTTP_HOST, $file3, $file2, $gdir,$gsub,$i,$j,$REMOTE_ADDR;" fullword ascii
      $s14 = "if (($conn_id) && (@ftp_login($conn_id, $g[1], $g[1]))) {" fullword ascii
      $s15 = "print \"\".exec(\"chmod 777 $private[5]\").\"\";" fullword ascii
      $s16 = "print \"\".exec(\"chmod 777 $private[7]\").\"\";" fullword ascii
      $s17 = "print \"\".exec(\"chmod 777 $private[6]\").\"\";" fullword ascii
      $s18 = "print \"\".exec(\"chmod 777 $private[2]\").\"\";" fullword ascii
      $s19 = "print \"\".exec(\"chmod 777 $private[8]\").\"\";" fullword ascii
      $s20 = "print \"\".exec(\"chmod 777 $private[3]\").\"\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 400KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _GFS_Web_Shell_gfs_sh_2 {
   meta:
      description = "php - from files GFS Web-Shell.txt, gfs_sh.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "94ffc6f08146d1c9b4c48609c7ca091bed192a87ef7c9031a525196d1749b16a"
      hash2 = "c8df75173ff2c9fae9980b311fbf23740b47481aec2175218d7ea99db5c31770"
   strings:
      $x1 = "$res=dump_table($_POST['tablename'], $_POST['dbname'],$_POST['host'], $_POST['username'], $_POST['pass']);" fullword ascii
      $s2 = "$res=run_sql($_POST['sql'], $_POST['dbname'],$_POST['host'], $_POST['username'], $_POST['pass']);" fullword ascii
      $s3 = "echo \"<tr bgcolor=#ffff00><td alling=\\\"center\\\"><b><font  face=Verdana size=2>Run command: </b></td></tr><font size=-2>\";" fullword ascii
      $s4 = "save_file(stripslashes(base64_decode($prx1).$_POST['port'].base64_decode($prx2)),\"/var/tmp/gfs.pl\",getcwd());" fullword ascii
      $s5 = "$res=safe_mode_fuck($_POST['sfilename'],$_POST['host'], $_POST['username'], $_POST['pass'], $_POST['dbname']);" fullword ascii
      $s6 = "################## EXECUTE #####################################################" fullword ascii
      $s7 = "echo \"<td alling=\\\"center\\\"><input type=\\\"submit\\\" name=\\\"b_table\\\" value=\\\"Dump table\\\"></td>\";" fullword ascii
      $s8 = "echo \"<td alling=\\\"center\\\"><b>OpenFilename: </b></td><td alling=\\\"center\\\"><b>DumpFilename: </b></td></tr>\";" fullword ascii
      $s9 = "echo(\"<td alling=\\\"center\\\"><input type=\\\"submit\\\" name=\\\"b_dfilename\\\" value=\\\"Dump table\\\"></td>\");" fullword ascii
      $s10 = "echo \"<tr><td alling=center>BruteFTP:  </td><td alling=center><b><font color=green> localhost </b></font></td></tr>\";" fullword ascii
      $s11 = "$res=show_tables($_POST['dbname'],$_POST['host'], $_POST['username'], $_POST['pass']);" fullword ascii
      $s12 = "$s=\"Dump in \".$dfilename.\" from \".$_POST['tablename'].\":\";" fullword ascii
      $s13 = "ex(\"perl /var/tmp/gfs.pl \".$_POST['ip'].\" \".$_POST['port'].\" &\");" fullword ascii
      $s14 = "echo \"<tr bgcolor=#00ff00><td alling=\\\"center\\\"><b>Example lib: </b>login:pass</td></tr>\";" fullword ascii
      $s15 = "echo \"<td alling=\\\"center\\\"><input type=\\\"submit\\\" name=\\\"b_base\\\" value=\\\"Dump DB\\\"></td>\";" fullword ascii
      $s16 = "echo \"<td alling=\\\"center\\\"></td><td alling=\\\"center\\\"><b>DumpFilename: </b></td></tr>\";" fullword ascii
      $s17 = "echo \"<tr><td alling=\\\"center\\\"><b>Target: </b><input type=\\\"text\\\" name=\\\"tfilename\\\"" fullword ascii
      $s18 = "echo \"<tr bgcolor=#ffff00><td alling=\\\"center\\\"><b><font  face=Verdana size=2>Bind Port: </b></td></tr><font size=-2>\";" fullword ascii
      $s19 = "if (ftp_login($conn_id,$lib[$kk],$lib[$kk+1])){" fullword ascii
      $s20 = "if (ftp_login($conn_id, $v, $lib[$kk])){" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 200KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _Mysql_interface_v1_0_MySQL_Web_Interface_Version_0_8_3 {
   meta:
      description = "php - from files Mysql interface v1.0.txt, MySQL Web Interface Version 0.8.php"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "b373730fd4b62553b6a5af092835918243ea29bef6f559849fc8131c935cb6cf"
      hash2 = "7be230cab89ef568b598e64885fe315c8983f300167a21b8279cc94cb99317a0"
   strings:
      $s1 = "$mysqlHandle = mysql_pconnect( $HOSTNAME, $USERNAME, $PASSWORD );" fullword ascii
      $s2 = "header(\"Content-disposition: filename=$filename.sql\");" fullword ascii
      $s3 = "echo \"<font color=blue>[$USERNAME]</font> - \\n\";" fullword ascii
      $s4 = "if( $command == \"flush_logs\" ) {" fullword ascii
      $s5 = "else if( $action == \"dumpTable\" || $action == \"dumpDB\" ) {" fullword ascii
      $s6 = "if( $command == \"flush_hosts\" ) {" fullword ascii
      $s7 = "2147483647" ascii /* hex encoded string '!GH6G' */
      $s8 = "global $PHP_SELF, $USERNAME, $PASSWORD, $action, $dbname, $tablename;" fullword ascii
      $s9 = "if( $command == \"\" || substr( $command, 0, 5 ) == \"flush\" ) {" fullword ascii
      $s10 = "if( $command == \"flush_privileges\" ) {" fullword ascii
      $s11 = "if( $action == \"logon\" || $action == \"\" || $action == \"logout\" )" fullword ascii
      $s12 = "* -------------------------------" fullword ascii
      $s13 = "<th>Type</th><th>&nbspM&nbsp</th><th>&nbspD&nbsp</th><th>unsigned</th><th>zerofill</th><th>binary</th>" fullword ascii
      $s14 = "if( $var == \"mysql_web_admin_password\" ) $PASSWORD = $value;" fullword ascii
      $s15 = "echo \"<input type=hidden name=action value=logon_submit>\\n\";" fullword ascii
      $s16 = "$queryStr = ereg_replace( \"_\", \" \", $command );" fullword ascii
      $s17 = "setcookie( \"mysql_web_admin_password\", $password );" fullword ascii
      $s18 = "echo \"<a href='$PHP_SELF?action=logon'>Logon</a>\\n\";" fullword ascii
      $s19 = "if( $action == \"dumpTable\" )" fullword ascii
      $s20 = "setcookie( \"mysql_web_admin_password\" );" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 100KB and ( 8 of them )
      ) or ( all of them )
}

rule _GFS_web_shell_ver_3_1_7___PRiV8_GFS_Web_Shell_gfs_sh_NetworkFileManagerPHP_NFM_1_8_4 {
   meta:
      description = "php - from files GFS web-shell ver 3.1.7 - PRiV8.txt, GFS Web-Shell.txt, gfs_sh.txt, NetworkFileManagerPHP.txt, NFM 1.8.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "b42c3f5fcbb8a3bfefde7c77cef73cd6f1efd1f024366ccc0db1632877756c92"
      hash2 = "94ffc6f08146d1c9b4c48609c7ca091bed192a87ef7c9031a525196d1749b16a"
      hash3 = "c8df75173ff2c9fae9980b311fbf23740b47481aec2175218d7ea99db5c31770"
      hash4 = "0863907cbabc1679e00a99f84c5adc3ff4daab11aa0df970e37f051c770d31ed"
      hash5 = "c9a73b6128994707f4cce41ac8c80bf522cab11e413871718607b8e1bfa4683c"
   strings:
      $s1 = "$port[4000] = \"icq, command-n-conquer and shell nfm\";" fullword ascii
      $s2 = "$port[49] = \"TACACS, Login Host Protocol\";" fullword ascii
      $s3 = "$port[543] = \"KLogin, AppleShare over IP\";" fullword ascii
      $s4 = "$port[3] = \"Compression Process\";" fullword ascii
      $s5 = "$port[513] = \"who, rlogin\";" fullword ascii
      $s6 = "$port[45] = \"Message Processing Module [recv]\";" fullword ascii
      $s7 = "$port[2301] = \"Compaq Insight Management Web Agents\";" fullword ascii
      $s8 = "$port[23456] = \"EvilFTP\";" fullword ascii
      $s9 = "$port[512] = \"biff, rexec\";" fullword ascii
      $s10 = "$port[69] = \"Trivial File Transfer Protocol (tftp)\";" fullword ascii
      $s11 = "$port[115] = \"sftp (Simple File Transfer Protocol)\";" fullword ascii
      $s12 = "$port[27] = \"ETRN (NSW User System FE)\";" fullword ascii
      $s13 = "$port[104] = \"ACR-NEMA Digital Imag. & Comm. 300\";" fullword ascii
      $s14 = "$port[45000] = \"Cisco NetRanger postofficed\";" fullword ascii
      $s15 = "$port[25] = \"SMTP (Simple Mail Transfer)\";" fullword ascii
      $s16 = "$port[3031] = \"Apple AgentVU\";" fullword ascii
      $s17 = "$port[5555] = \"Personal Agent\";" fullword ascii
      $s18 = "$port[705] = \"AgentX for SNMP\";" fullword ascii
      $s19 = "$port[81] = \"HOSTS2 Name Serve\";" fullword ascii
      $s20 = "$port[57] = \"MTP (any private terminal access)\";" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _Loaderz_WEB_Shell_load_shell_5 {
   meta:
      description = "php - from files Loaderz WEB Shell.txt, load_shell.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "807e193eed7caab0a49555039a2391f8dbe6ec6fc4a001ba6292293f86e6ef81"
      hash2 = "58b95daea4bbef83e299f5a4e67d060e12ebe2a9edfff6abce2d8880d839ffb7"
   strings:
      $x1 = "<center>Coded by Loader <a href=\"http://pro-hack.ru\">Pro-Hack.RU</a></center>" fullword ascii
      $x2 = "echo \"uname:\" . execute('uname -a') . \"<br>\";" fullword ascii
      $x3 = "print \"<center><div id=logostrip>Something is wrong. Download - IS NOT OK</div></center>\";" fullword ascii
      $s4 = "print \"<center><div id=logostrip>Download - OK. (\".$sizef.\"" fullword ascii
      $s5 = "/* Loader'z WEB Shell v 0.1.0.2 {15 " fullword ascii
      $s6 = "echo \"<center><div id=logostrip>Command: $cmd<br><textarea cols=100 rows=20>\";" fullword ascii
      $s7 = "copy($HTTP_POST_FILES[\"userfile\"][\"tmp_name\"],$HTTP_POST_FILES[\"userfile\"][\"name\"]);" fullword ascii
      $s8 = "<b>Temp path</b><input type=\\\"text\\\" name=\\\"installpath\\\" value=\\\"\" . getcwd() . \"\\\"></td><td>" fullword ascii
      $s9 = "if(isset($_POST['post']) and $_POST['post'] == \"yes\" and @$HTTP_POST_FILES[\"userfile\"][name] !== \"\")" fullword ascii
      $s10 = "<input type=\\\"submit\\\" name=\\\"submit\\\" value=\\\"Exec\\\" id=input></form></center></div>\";" fullword ascii
      $s11 = "<table id=tb><tr><td>Command:<INPUT type=\\\"text\\\" name=\\\"cmd\\\" size=30 value=\\\"$cmd\\\"></td></tr></table>" fullword ascii
      $s12 = "echo \" Exec here: \" . ini_get('safe_mode_exec_dir');" fullword ascii
      $s13 = "echo \"<center><div id=logostrip>Results of PHP execution<br><br>\";" fullword ascii
      $s14 = "<title>Loader'z WEB shell</title>" fullword ascii
      $s15 = "echo decode(execute($cmd));" fullword ascii
      $s16 = "function execute($com)" fullword ascii
      $s17 = "$s.=sprintf(\"%1s%1s%1s\", $world['read'], $world['write'], $world['execute']);" fullword ascii
      $s18 = "$s.=sprintf(\"%1s%1s%1s\", $owner['read'], $owner['write'], $owner['execute']);" fullword ascii
      $s19 = "$s.=sprintf(\"%1s%1s%1s\", $group['read'], $group['write'], $group['execute']);" fullword ascii
      $s20 = "if( $mode & 0x400 ) $group[\"execute\"] = ($group['execute']=='x') ? 's' : 'S';" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 40KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _GFS_web_shell_ver_3_1_7___PRiV8_GFS_Web_Shell_gfs_sh_6 {
   meta:
      description = "php - from files GFS web-shell ver 3.1.7 - PRiV8.txt, GFS Web-Shell.txt, gfs_sh.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "b42c3f5fcbb8a3bfefde7c77cef73cd6f1efd1f024366ccc0db1632877756c92"
      hash2 = "94ffc6f08146d1c9b4c48609c7ca091bed192a87ef7c9031a525196d1749b16a"
      hash3 = "c8df75173ff2c9fae9980b311fbf23740b47481aec2175218d7ea99db5c31770"
   strings:
      $x1 = "$dump=down_tb($_POST['tablename'], $_POST['dbname'],$_POST['host'], $_POST['username'], $_POST['pass']);" fullword ascii
      $s2 = "echo down_tb($_POST['tablename'], $_POST['dbname'],$_POST['host'], $_POST['username'], $_POST['pass']);" fullword ascii
      $s3 = "header(\"Content-disposition: attachment; filename=\\\"\".$_POST['tablename'].\".dmp\\\";\");" fullword ascii
      $s4 = "echo \"<b>RemoteAddressIfProxy:</b><font color=red>\".$HTTP_SERVER_VARS['HTTP_X_FORWARDED_FOR'].\"</font>\";" fullword ascii
      $s5 = "$filedump=fread($file,filesize($_POST['fname']));" fullword ascii
      $s6 = "die(\"<b>Error dump!</b><br> table=\".$_POST['tablename'].\"<br> db=\".$_POST['dbname'].\"<br> host=\".$_POST['host'].\"<br> use" ascii
      $s7 = "die(\"<b>Error dump!</b><br> table=\".$_POST['tablename'].\"<br> db=\".$_POST['dbname'].\"<br> host=\".$_POST['host'].\"<br> use" ascii
      $s8 = "header(\"Content-disposition: attachment; filename=\\\"\".$filename.\"\\\";\");" fullword ascii
      $s9 = "echo \"<b>RemoteAddress:</b><font color=red>\".$HTTP_SERVER_VARS['REMOTE_ADDR'].\"</font><br>\";" fullword ascii
      $s10 = "$prx2=\"XCI7DQoNCnN1YiBwcmVmaXggew0KIG15ICRub3cgPSBsb2NhbHRpbWU7DQoNCiBqb2luIFwiXCIsIG1hcCB7IFwiWyRub3ddIFskeyR9XSAk" fullword ascii
      $s11 = "echo \"user=\".@get_current_user().\" uid=\".@getmyuid().\" gid=\".@getmygid()." fullword ascii
      $s12 = "QogICBleGl0KDApOw0KIH0NCiBzdHJjYXQocm1zLCBhcmd2WzBdKTsNCiBzeXN0ZW0ocm1zKTsgIA0KIGR1cDIoZmQsIDApOw0KIGR1cDIoZmQsIDEp" fullword ascii
      $s13 = "7DQogICByZWFkKG5ld2ZkLGJ1ZixzaXplb2YoYnVmKSk7DQogICBpZiAoIWNocGFzcyhhcmd2WzJdLGJ1ZikpDQogICBzeXN0ZW0oImVjaG8gd2VsY2" fullword ascii
      $s14 = "A8c3lzL3NvY2tldC5oPg0KI2luY2x1ZGUgPG5ldGluZXQvaW4uaD4NCiNpbmNsdWRlIDxlcnJuby5oPg0KaW50IG1haW4oYXJnYyxhcmd2KQ0KaW50I" fullword ascii
      $s15 = "KSk7DQogc2luLnNpbl9hZGRyLnNfYWRkciA9IGluZXRfYWRkcihhcmd2WzFdKTsgDQogYnplcm8oYXJndlsxXSxzdHJsZW4oYXJndlsxXSkrMStzdHJ" fullword ascii
      $s16 = "SAtZiAiOyANCiBkYWVtb24oMSwwKTsNCiBzaW4uc2luX2ZhbWlseSA9IEFGX0lORVQ7DQogc2luLnNpbl9wb3J0ID0gaHRvbnMoYXRvaShhcmd2WzJd" fullword ascii
      $s17 = "BtYWluKGludCBhcmdjLCBjaGFyICphcmd2W10pDQp7DQogaW50IGZkOw0KIHN0cnVjdCBzb2NrYWRkcl9pbiBzaW47DQogY2hhciBybXNbMjFdPSJyb" fullword ascii
      $s18 = "$port_c=\"I2luY2x1ZGUgPHN0ZGlvLmg+DQojaW5jbHVkZSA8c3RyaW5nLmg+DQojaW5jbHVkZSA8c3lzL3R5cGVzLmg+DQojaW5jbHVkZS" fullword ascii
      $s19 = "$res=shell_exec($comd);" fullword ascii
      $s20 = "$prx1=\"IyEvaG9tZS9tZXJseW4vYmluL3BlcmwgLXcNCiMjIw0KIyMjaHR0cDovL2ZvcnVtLndlYi1oYWNrLnJ1L2luZGV4LnBocD9zaG93dG9waWM9" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 200KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _KAdot_Universal_Shell_v0_1_6_KA_uShell_0_1_6_7 {
   meta:
      description = "php - from files KAdot Universal Shell v0.1.6.php, KA_uShell 0.1.6.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "d7a5cca2bdf63841127a1618cb25e8e9a5892269fc687ca9a795b895bdbd4ed9"
      hash2 = "06d8c97448db0b9c7790e0d94fcb8db79162ea23ac65f1f74e687f3186017f73"
   strings:
      $s1 = "if (empty($_POST['wser'])) {$wser = \"whois.ripe.net\";} else $wser = $_POST['wser'];" fullword ascii
      $s2 = "header('WWW-Authenticate: Basic realm=\"KA_uShell\"');" fullword ascii
      $s3 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}" fullword ascii
      $s4 = "//PHP Eval Code execution" fullword ascii
      $s5 = "$login = \"admin\";" fullword ascii
      $s6 = "$uploadfile = $_POST['path'].$_FILES['file']['name'];" fullword ascii
      $s7 = "<form enctype=\"multipart/form-data\" action=\"$self\" method=\"POST\">" fullword ascii
      $s8 = "$$sern <input size=\"50\" type=\"text\" name=\"c\"><input align=\"right\" type=\"submit\" value=\"Enter\">" fullword ascii
      $s9 = "<td><input size=\"40\" type=\"text\" name=\"wser\" value=\"whois.ripe.net\"></td>" fullword ascii
      $s10 = "ER']<>$login)" fullword ascii
      $s11 = ":<b>\" .base64_decode($_POST['tot']). \"</b>\";" fullword ascii
      $s12 = "<td><input size=\"48\" value=\"$docr/\" name=\"path\" type=\"text\"><input type=\"submit\" value=\"" fullword ascii
      $s13 = "if (copy($_FILES['file']['tmp_name'], $uploadfile)) {" fullword ascii
      $s14 = "if (isset($_POST['wq']) && $_POST['wq']<>\"\") {" fullword ascii
      $s15 = "if (!empty($_POST['tot']) && !empty($_POST['tac'])) {" fullword ascii
      $s16 = "elseif (!empty($_POST['ac'])) {$ac = $_POST['ac'];}" fullword ascii
      $s17 = "<input type=\"hidden\" name=\"ac\" value=\"shell\">" fullword ascii
      $s18 = "if(empty($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW']<>$pass || empty($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_US" ascii
      $s19 = "passthru($_POST['c']);" fullword ascii
      $s20 = "if (!empty($_GET['ac'])) {$ac = $_GET['ac'];}" fullword ascii
   condition:
      ( uint16(0) == 0x213c and filesize < 10KB and ( 8 of them )
      ) or ( all of them )
}

rule _NetworkFileManagerPHP_NetworkFileManagerPHP_NFM_1_8_NFM_1_8_8 {
   meta:
      description = "php - from files NetworkFileManagerPHP.txt, NetworkFileManagerPHP.txt, NFM 1.8.txt, NFM 1.8.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "0863907cbabc1679e00a99f84c5adc3ff4daab11aa0df970e37f051c770d31ed"
      hash2 = "0863907cbabc1679e00a99f84c5adc3ff4daab11aa0df970e37f051c770d31ed"
      hash3 = "c9a73b6128994707f4cce41ac8c80bf522cab11e413871718607b8e1bfa4683c"
      hash4 = "c9a73b6128994707f4cce41ac8c80bf522cab11e413871718607b8e1bfa4683c"
   strings:
      $s1 = "header(\"Content-type: image/jpeg\");" fullword ascii
      $s2 = "$csvdump.=\"\\n\";" fullword ascii
      $s3 = "fputs($fp,\"\\$dbhost='$dbhost';\\n\");" fullword ascii
      $s4 = "$buf = fgets($fpip, 100);" fullword ascii
      $s5 = "$char = fgetc($fp);" fullword ascii
      $s6 = "$counter = $counter + 1;" fullword ascii
      $s7 = "fputs($fp,\"\\$dbpass='$dbpass';\\n\");" fullword ascii
      $s8 = "fputs($fp,\"\\$dbuser='$dbuser';\\n\");" fullword ascii
      $s9 = "$fp=fopen($secu_config,\"w\");" fullword ascii
      $s10 = "$time = date(\"d/m/y H:i\",filemtime($fullpath));" fullword ascii
      $s11 = "$perm = permissions(fileperms($fullpath));" fullword ascii
      $s12 = "ignore_user_abort(1);" fullword ascii
      $s13 = "$st = str_replace(\">\", \"&gt;\", $st);" fullword ascii
      $s14 = "$st = str_replace(\"<\", \"&lt;\", $st);" fullword ascii
      $s15 = "ereg(\"^([0-9a-zA-Z]{1,})\\:\",$buf,$g);" fullword ascii
      $s16 = "$st = str_replace(\"&\", \"&amp;\", $st);" fullword ascii
      $s17 = "echo \"<br><TABLE CELLPADDING=0 CELLSPACING=0 bgcolor=#184984 BORDER=1 width=500 align=center bordercolor=#808080 bordercolorlig" ascii
      $s18 = "readdirdata($tm);" fullword ascii
      $s19 = "$boundary = uniqid(\"NextPart_\");" fullword ascii
      $s20 = "$fpip = @fopen ($filename, \"r\");" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

