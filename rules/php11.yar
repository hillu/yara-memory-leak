/*
   YARA Rule Set
   Author: WatcherLab
   Date: 2019-01-02
   Identifier: php
*/

/* Rule Set ----------------------------------------------------------------- */


rule simple_cmd {
   meta:
      description = "php - file simple_cmd.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "1927b19ccfadbc31b0889958ca5bb8bae178a006c8b47e8e708eb5ecb6819931"
   strings:
      $s1 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword ascii
      $s2 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword ascii
      $s3 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword ascii
      $s4 = "<title>G-Security Webshell</title>" fullword ascii
      $s5 = "<form method=POST>" fullword ascii
      $s6 = "style=\"background:#000000;color:#ffffff;\">" fullword ascii
      $s7 = "<body bgcolor=#000000 text=#ffffff \">" fullword ascii
   condition:
      uint16(0) == 0x683c and filesize < 1KB and
      all of them
}





rule simple_backdoor {
   meta:
      description = "php - file simple-backdoor.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "469ee71b23546e41924c4f95512d8f993dd329427f3a6a3f4190058ca4acca97"
   strings:
      $x1 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword ascii
      $s2 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->" fullword ascii
      $s3 = "<!--    http://michaeldaw.org   2006    -->" fullword ascii
      $s4 = "system($cmd);" fullword ascii
      $s5 = "$cmd = ($_REQUEST['cmd']);" fullword ascii
      $s6 = "if(isset($_REQUEST['cmd'])){" fullword ascii
   condition:
      uint16(0) == 0x213c and filesize < 1KB and
      1 of ($x*) and all of them
}


rule Uploader {
   meta:
      description = "php - file Uploader.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "33623f97eb8375943eb6852c95ec6dd3a993108b2c6e9954ea55e9ef7be52216"
   strings:
      $s1 = "<FORM ENCTYPE=\"multipart/form-data\" ACTION=\"uploader.php\" METHOD=\"POST\">" fullword ascii
      $s2 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword ascii
      $s3 = "Send this file: <INPUT NAME=\"userfile\" TYPE=\"file\">" fullword ascii
      $s4 = "<INPUT TYPE=\"hidden\" name=\"MAX_FILE_SIZE\" value=\"100000\">" fullword ascii
      $s5 = "<INPUT TYPE=\"submit\" VALUE=\"Send\">" fullword ascii
   condition:
      uint16(0) == 0x463c and filesize < 1KB and
      all of them
}

rule Sincap_1_0 {
   meta:
      description = "php - file Sincap 1.0.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "d4df10e8eb2db71910506027347bf96ef2481d41f5c617dcf24b0bfa08889a8d"
   strings:
      $s1 = "<img border=\"0\" src=\"http://www.aventgrup.net/avlog.gif\"></td>" fullword ascii
      $s2 = "info@aventgrup.net</font></a><font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#858585\">&nbsp;</font></td>" fullword ascii
      $s3 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1254\">" fullword ascii
      $s4 = "<font color=\"#858585\" face=\"Verdana\" style=\"font-size: 8pt\">www.aventgrup.net&nbsp;<br>" fullword ascii
      $s5 = "<meta http-equiv=\"Content-Language\" content=\"tr\">" fullword ascii
      $s6 = "<font face=\"Verdana\" style=\"font-size: 8pt; font-weight: 700\" color=\"#000000\">&nbsp;Referans</font></td>" fullword ascii
      $s7 = "<font face=\"Verdana\" style=\"font-size: 8pt; font-weight: 700\" color=\"#000000\">&nbsp;Oturum " fullword ascii
      $s8 = "<font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#000000\">&nbsp;<?echo $is;?></font></td>" fullword ascii
      $s9 = "<font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#000000\">&nbsp;<?echo $degerT;?></font></td>" fullword ascii
      $s10 = "<font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#000000\">&nbsp;<?echo $deger1;?></font></td>" fullword ascii
      $s11 = "<meta name=\"ProgId\" content=\"FrontPage.Editor.Document\">" fullword ascii
      $s12 = "<meta name=\"GENERATOR\" content=\"Microsoft FrontPage 6.0\">" fullword ascii
      $s13 = "<table border=\"0\" width=\"100%\" id=\"table1\" cellspacing=\"0\" cellpadding=\"0\" height=\"108\">" fullword ascii
      $s14 = "<font face=\"Verdana\" style=\"font-size: 8pt; font-weight: 700\" color=\"#000000\">&nbsp;S. " fullword ascii
      $s15 = "<font color=\"#E5E5E5\" style=\"font-size: 8pt; font-weight: 700\" face=\"Arial\">&nbsp; " fullword ascii
      $s16 = "<font face=\"Verdana\" style=\"font-size: 8pt; text-decoration: none\" color=\"#C0C0C0\">" fullword ascii
      $s17 = "</font></span><a href=\"mailto:shopen@aventgrup.net\">" fullword ascii
      $s18 = "<font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#000000\">&nbsp;-</td>" fullword ascii
      $s19 = "<title>:: AventGrup ::.. - Sincap 1.0 | Session(Oturum) B" fullword ascii
      $s20 = "<font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#B7B7B7\">" fullword ascii
   condition:
      uint16(0) == 0x683c and filesize < 10KB and
      8 of them
}




/* Super Rules ------------------------------------------------------------- */

rule _Small_Web_Shell_by_ZaCo_zacosmall_0 {
   meta:
      description = "php - from files Small Web Shell by ZaCo.txt, zacosmall.txt"
      author = "WatcherLab"
      date = "2019-01-02"
      hash1 = "b3ea105d85f8c99d6423abcfb29601215b73dbfcd5866be2c789ef44c73dee2f"
      hash2 = "addb8577594a550a3c7853251ea227df7af8c8a0878d3461020226bd3e1dd9ba"
   strings:
      $x1 = "header(\"Content-Disposition: attachment; filename=\\\"dump_{$db_dump}.sql\".($archive=='none'?'':'.gz').\"\\\"\\n\\n\");" fullword ascii
      $s2 = "$table_dump=isset($_POST['table_dump'])?$_POST['table_dump']:'';" fullword ascii
      $s3 = "$result2=mysql_query('select * from `'.$table_dump.'`',$mysql_link);" fullword ascii
      $s4 = "Header('Content-Disposition: attachment; filename=\"'.str_replace('/','-',$fname).\".gz\\n\\n\");" fullword ascii
      $s5 = "$db_dump=isset($_POST['db_dump'])?$_POST['db_dump']:'';" fullword ascii
      $s6 = "header('Content-Length: '.strlen($dump_file).\"\\n\");" fullword ascii
      $s7 = "Header('Content-Disposition: attachment; filename=\"'.str_replace('/','-',$fname).\"\\n\\n\");" fullword ascii
      $s8 = "if(!(@mysql_select_db($db_dump,$mysql_link)))echo('DB error');" fullword ascii
      $s9 = "<input name='action' value='download' type=submit onclick=\"work_dir.value=document.main_form.work_dir.value;\">" fullword ascii
      $s10 = "<tr><td>DB :</td><td><input type=text name='db_dump' value='<?=$db?>'></td></tr>" fullword ascii
      $s11 = "$dump_file.=($rows2[$k]==''?'null);':'\\''.addslashes($rows2[$k]).'\\');').\"\\n\";" fullword ascii
      $s12 = "$result2=@mysql_query('show columns from `'.$table_dump.'`',$mysql_link);" fullword ascii
      $s13 = "<tr><td>Only Table :</td><td><input type=text name='table_dump'></td></tr>" fullword ascii
      $s14 = "if(!$result2)$dump_file.='#error table '.$rows[0];" fullword ascii
      $s15 = "if(!@copy($_FILES[\"filename\"][\"tmp_name\"], $work_dir.$f)) echo('Upload is failed');" fullword ascii
      $s16 = "if(!$result2)echo('error table '.$table_dump);" fullword ascii
      $s17 = "$page=isset($_POST['page'])?$_POST['page']:(isset($_SERVER['QUERY_STRING'])?$_SERVER['QUERY_STRING']:'');" fullword ascii
      $s18 = "$temp_file=isset($_POST['temp_file'])?'on':'nn';" fullword ascii
      $s19 = "$dump_file.=$rows2[$k]==''?'null,':'\\''.addslashes($rows2[$k]).'\\',';" fullword ascii
      $s20 = "<input name='action' value='cmd' type=submit onclick=\"work_dir.value=document.main_form.work_dir.value;\">" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 50KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

