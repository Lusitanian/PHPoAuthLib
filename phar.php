<?php
$phar = new Phar('OAuth.phar', 0, 'OAuth.phar');
$phar->buildFromDirectory ( 'src/OAuth' );
$stub = <<<'EOS'
<?php
function oauth_autoload($class)
{
	if ( substr ( $class, 0, 6 ) == 'OAuth\\' )
	{
		$path = 'phar://OAuth.phar/' . str_replace('\\', '/', substr ( $class, 6 ) ) . '.php';
		if ( is_file($path) )
			include $path;
	}
}
spl_autoload_register ( 'oauth_autoload', True );
try
{
	phar::mapPhar ( 'OAuth.phar' );
}
catch ( PharException $e )
{
	echo $e->getMessage();
	die ( 'Cannot initialize OAuth.phar' );
}
__HALT_COMPILER();
?>
EOS;
$phar->setStub ( $stub );
$phar->stopBuffering();
?>