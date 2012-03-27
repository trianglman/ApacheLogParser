<?php

function autoload($class) {
    $file = str_replace('apacheLogParser\\A','../a',$class.'.php');
    if(file_exists($file)){require_once($file);}
}
spl_autoload_register('autoload');
?>
