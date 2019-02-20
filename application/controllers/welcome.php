<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');

class Welcome extends CI_Controller {

	/**
	 * Index Page for this controller.
	 *
	 * Maps to the following URL
	 * 		http://example.com/index.php/welcome
	 *	- or -  
	 * 		http://example.com/index.php/welcome/index
	 *	- or -
	 * Since this controller is set as the default controller in 
	 * config/routes.php, it's displayed at http://example.com/
	 *
	 * So any other public methods not prefixed with an underscore will
	 * map to /index.php/welcome/<method_name>
	 * @see http://codeigniter.com/user_guide/general/urls.html
	 */
	public function index()
	{
		$this->load->view('welcome_message');

	}

	public function generarPdfController() {
        $this->load->helper('to_dompdf_pi_helper');
        $html = $this->load->view('welcome_message',NULL,true);
        generarPdf($html, 'reporte','letter','portrait');
    }
    

	//Genera 2810 passwords aleatorios
	public function experimento(){
		$this->load->library("danecrypt");
		echo "<table>";
		echo "<tr>";
		echo "<td>Sin Cifrar</td>";
		echo "<td>Cifrado</td>";
		echo "</tr>";
		for ($i=0; $i<7000; $i++){
			$CONpassword = $this->danecrypt->generarPassword();
			$SINpassword = $this->danecrypt->decode($CONpassword);
			echo "<tr>";
			echo "<td>".$SINpassword."</td>";
			echo "<td>".$CONpassword."</td>";
			echo "</tr>";
		}
		echo "</table>";
	}
	
	//Genera clave
	public function experimento2(){
		$this->load->library("danecrypt");
		$clave = 'F20000107';
	    $salt = '$6$tyR/&(ctyi';
		echo crypt($clave,$this->salt);
		 
	}
	
	public function aveClave(){
		$this->load->library("danecrypt");
		echo "<table>";
		echo "<tr>";
		echo "<td>Sin Cifrar</td>";
		echo "<td>Cifrado</td>";
		echo "</tr>";
		
			$CONpassword = 'b69a842549efa472926e1e45dc0cf6d2';
			$SINpassword = $this->danecrypt->decode($CONpassword);
			echo "<tr>";
			echo "<td>".$SINpassword."</td>";
			echo "<td>".$CONpassword."</td>";
			echo "</tr>";
		
		echo "</table>";
	}
	
	//Genera 2810 passwords aleatorios
	public function experimento3(){
		$this->load->library("danecrypt");
		echo "<table>";
		echo "<tr>";
		echo "<td>sin cifrar</td>";
		echo "<td>clave a generar</td>";
		echo "</tr>";
		
			$CONpassword = "Vanesa2017";
			$SINpassword = $this->danecrypt->encode($CONpassword);
			echo "<tr>";
			echo "<td>".$CONpassword."</td>";
			echo "<td>".$SINpassword."</td>";
			echo "</tr>";

		echo "</table>";
	}
	
	//Genera 2810 passwords aleatorios
	public function experimento4(){
		$this->load->library("danecrypt");
		echo "<table>";
		echo "<tr>";
		echo "<td>sin cifrar</td>";
		echo "<td>clave a generar</td>";
		echo "</tr>";
		$array[0] = "1032374256"   ;
		$array[1] = "1024486190"     ;
		$array[2] = "37333213"   ;
		$array[3] = "79698464"    ;
		$array[4] = "79762015"    ;
		$array[5] = "FNDNSANTANDER6";
		$array[6] = "FNDCESAR7"     ;
		$array[7] = "FNDANTIOQUIA8" ;
		$array[8] = "FNDMETA9"      ;
		$array[9] = "FNDSANTANDER0" ;
		$array[10] = "FNDCALDAS1"    ;
		$array[11] = "FNDTOLIMA2"    ;
		$array[12] = "FNDAMAZONAS3"  ;
		$array[13] = "FNDVAUPES4"    ;
		$array[14] = "FNDGUAINIA5"   ;
		$array[15] = "FNDARAUCA6"    ;
		$array[16] = "FNDCUND7"      ;
		$array[17] = "FNDBOGOTA8"    ;
		for ($i=0; $i<count($array); $i++){
			$CONpassword = $array[$i];
			$SINpassword = $this->danecrypt->encode($CONpassword);
			echo "<tr>";
			echo "<td>".$CONpassword."</td>";
			echo "<td>".$SINpassword."</td>";
			echo "</tr>";
		}
		echo "</table>";
	}
	
	public function experimento5(){
	//$key should have been previously generated in a cryptographically safe way, like openssl_random_pseudo_bytes
	$plaintext = "message to be encrypted";
	$cipher = "aes-128-gcm";
	if (in_array($cipher, openssl_get_cipher_methods()))
	{
		$ivlen = openssl_cipher_iv_length($cipher);
		$iv = openssl_random_pseudo_bytes($ivlen);
		$ciphertext = openssl_encrypt($plaintext, $cipher, $key, $options=0, $iv, $tag);
		//store $cipher, $iv, and $tag for decryption later
		$original_plaintext = openssl_decrypt($ciphertext, $cipher, $key, $options=0, $iv, $tag);
		echo $original_plaintext."\n";
	}
	
	//$key previously generated safely, ie: openssl_random_pseudo_bytes
	$plaintext = "message to be encrypted";
	$ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
	$iv = openssl_random_pseudo_bytes($ivlen);
	$ciphertext_raw = openssl_encrypt($plaintext, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
	$hmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true);
	$ciphertext = base64_encode( $iv.$hmac.$ciphertext_raw );

		//decrypt later....
		$c = base64_decode($ciphertext);
		$ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
		$iv = substr($c, 0, $ivlen);
		$hmac = substr($c, $ivlen, $sha2len=32);
		$ciphertext_raw = substr($c, $ivlen+$sha2len);
		$original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
		$calcmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true);
		if (hash_equals($hmac, $calcmac))//PHP 5.6+ timing attack safe comparison
		{
			echo $original_plaintext."\n";
		}
	}
	
	//Genera clave cnpv
	public function clavecnpv(){
		$contrasena = "Admin123456";
        $usuario = "naibafsystems@gmail.com";
        $contrasena_new = md5($contrasena);
        $contrasena_new = $contrasena_new.$usuario;
        $clave = hash('sha512', $contrasena_new);
        echo $clave."<br>"; 
	}
	
	//Genera clave cnpv
	public function clavecnpv2(){
		/*generar para varias**/
		echo "<table>";
		echo "<tr>";
		echo "<td>contrasena</td>";
		echo "<td>usuario</td>";
		echo "<td>clave</td>";
		echo "</tr>";
		$array[0] = "19433992";
		$array[1] = "39647515";
		$array[2] = "1024487459";
		$array[3] = "52172147";


$array2[0] = "digitador830";
$array2[1] = "digitador826";
$array2[2] = "digitador827";
$array2[3] = "digitador828";



		
		for ($i=0; $i<count($array); $i++){
			$contrasena = $array[$i];
			$usuario = $array2[$i];
			$cifrado = md5($contrasena);
			$cifrado = $cifrado.$usuario;
			$clave = hash('sha512', $cifrado);
			echo "<tr>";
			echo "<td>".$contrasena."</td>";
			echo "<td>".$usuario."</td>";
			echo "<td>".$clave."</td>";
			echo "</tr>";
		}
		echo "</table>";		
	}
	
	//Genera clave lea
	public function clavelea(){
		$password = sha1("AK7321MO3");
        $user = "lea1010digitador3";
		$encryptClave = $this->encode($password, $user);
		$result = $encryptClave;
		echo $result."<br>"; 
	}
	
	//Genera clave lea
	public function clavelea2(){
		/*generar para varias**/
		echo "<table>";
		echo "<tr>";
		echo "<td>contrasena</td>";
		echo "<td>usuario</td>";
		echo "<td>clave</td>";
		echo "</tr>";
		
		$array[0] = "AK7321MO3";
		$array[1] = "AK7321MO4";
		$array[2] = "AK7321MO5";
		$array[3] = "AK7321MO6";
		$array[4] = "AK7321MO7";
		$array[5] = "AK7321MO8";
		$array[6] = "AK7321MO9";
		$array[7] = "AK7321MO10";
		$array[8] = "AK7321MO11";
		$array[9] = "AK7321MO12";
		$array[10] = "AK7321MO13";
		$array[11] = "AK7321MO14";
		$array[12] = "AK7321MO15";
		$array[13] = "AK7321MO16";
		$array[14] = "AK7321MO17";
		$array[15] = "AK7321MO18";
		$array[16] = "AK7321MO19";
		$array[17] = "AK7321MO20";
		$array[18] = "AK7321MO21";
		$array[19] = "AK7321MO22";
		$array[20] = "AK7321MO23";
		$array[21] = "AK7321MO24";
		$array[22] = "AK7321MO25";
		$array[23] = "AK7321MO26";
		$array[24] = "AK7321MO27";
		$array[25] = "AK7321MO28";
		$array[26] = "AK7321MO29";
		$array[27] = "AK7321MO30";
		$array[28] = "AK7321MO31";
		$array[29] = "AK7321MO32";
		$array[30] = "AK7321MO33";
		$array[31] = "AK7321MO34";
		$array[32] = "AK7321MO35";
		$array[33] = "AK7321MO36";
		$array[34] = "AK7321MO37";
		$array[35] = "AK7321MO38";
		$array[36] = "AK7321MO39";
		$array[37] = "AK7321MO40";
		$array[38] = "AK7321MO41";
		$array[39] = "AK7321MO42";
		$array[40] = "AK7321MO43";
		$array[41] = "AK7321MO44";
		$array[42] = "AK7321MO45";
		$array[43] = "AK7321MO46";
		$array[44] = "AK7321MO47";
		$array[45] = "AK7321MO48";
		$array[46] = "AK7321MO49";
		$array[47] = "AK7321MO50";
		$array[48] = "AK7321MO51";
		$array[49] = "AK7321MO52";
		$array[50] = "AK7321MO53";
		$array[51] = "AK7321MO54";
		$array[52] = "AK7321MO55";
		$array[53] = "AK7321MO56";
		$array[54] = "AK7321MO57";
		$array[55] = "AK7321MO58";
		$array[56] = "AK7321MO59";
		$array[57] = "AK7321MO60";
		$array[58] = "AK7321MO61";
		$array[59] = "AK7321MO62";
		$array[60] = "AK7321MO63";
		$array[61] = "AK7321MO64";
		$array[62] = "AK7321MO65";
		$array[63] = "AK7321MO66";
		$array[64] = "AK7321MO67";
		$array[65] = "AK7321MO68";
		$array[66] = "AK7321MO69";
		$array[67] = "AK7321MO70";
		$array[68] = "AK7321MO71";
		$array[69] = "AK7321MO72";
		$array[70] = "AK7321MO73";
		$array[71] = "AK7321MO74";
		$array[72] = "AK7321MO75";
		$array[73] = "AK7321MO76";
		$array[74] = "AK7321MO77";
		$array[75] = "AK7321MO78";
		$array[76] = "AK7321MO79";
		$array[77] = "AK7321MO80";
		$array[78] = "AK7321MO81";
		$array[79] = "AK7321MO82";
		$array[80] = "AK7321MO83";
		$array[81] = "AK7321MO84";
		$array[82] = "AK7321MO85";
		$array[83] = "AK7321MO86";
		$array[84] = "AK7321MO87";
		$array[85] = "AK7321MO88";
		$array[86] = "AK7321MO89";
		$array[87] = "AK7321MO90";
		$array[88] = "AK7321MO91";
		$array[89] = "AK7321MO92";
		$array[90] = "AK7321MO93";
		$array[91] = "AK7321MO94";
		$array[92] = "AK7321MO95";
		$array[93] = "AK7321MO96";
		$array[94] = "AK7321MO97";
		$array[95] = "AK7321MO98";
		$array[96] = "AK7321MO99";
		$array[97] = "AK7321MO100";
		$array[98] = "AK7321MO101";
		$array[99] = "AK7321MO102";
		$array[100] = "AK7321MO103";


		$array2[0] = "lea1010digitador3";
		$array2[1] = "lea1010digitador4";
		$array2[2] = "lea1010digitador5";
		$array2[3] = "lea1010digitador6";
		$array2[4] = "lea1010digitador7";
		$array2[5] = "lea1010digitador8";
		$array2[6] = "lea1010digitador9";
		$array2[7] = "lea1010digitador10";
		$array2[8] = "lea1010digitador11";
		$array2[9] = "lea1010digitador12";
		$array2[10] = "lea1010digitador13";
		$array2[11] = "lea1010digitador14";
		$array2[12] = "lea1010digitador15";
		$array2[13] = "lea1010digitador16";
		$array2[14] = "lea1010digitador17";
		$array2[15] = "lea1010digitador18";
		$array2[16] = "lea1010digitador19";
		$array2[17] = "lea1010digitador20";
		$array2[18] = "lea1010digitador21";
		$array2[19] = "lea1010digitador22";
		$array2[20] = "lea1010digitador23";
		$array2[21] = "lea1010digitador24";
		$array2[22] = "lea1010digitador25";
		$array2[23] = "lea1010digitador26";
		$array2[24] = "lea1010digitador27";
		$array2[25] = "lea1010digitador28";
		$array2[26] = "lea1010digitador29";
		$array2[27] = "lea1010digitador30";
		$array2[28] = "lea1010digitador31";
		$array2[29] = "lea1010digitador32";
		$array2[30] = "lea1010digitador33";
		$array2[31] = "lea1010digitador34";
		$array2[32] = "lea1010digitador35";
		$array2[33] = "lea1010digitador36";
		$array2[34] = "lea1010digitador37";
		$array2[35] = "lea1010digitador38";
		$array2[36] = "lea1010digitador39";
		$array2[37] = "lea1010digitador40";
		$array2[38] = "lea1010digitador41";
		$array2[39] = "lea1010digitador42";
		$array2[40] = "lea1010digitador43";
		$array2[41] = "lea1010digitador44";
		$array2[42] = "lea1010digitador45";
		$array2[43] = "lea1010digitador46";
		$array2[44] = "lea1010digitador47";
		$array2[45] = "lea1010digitador48";
		$array2[46] = "lea1010digitador49";
		$array2[47] = "lea1010digitador50";
		$array2[48] = "lea1010digitador51";
		$array2[49] = "lea1010digitador52";
		$array2[50] = "lea1010digitador53";
		$array2[51] = "lea1010digitador54";
		$array2[52] = "lea1010digitador55";
		$array2[53] = "lea1010digitador56";
		$array2[54] = "lea1010digitador57";
		$array2[55] = "lea1010digitador58";
		$array2[56] = "lea1010digitador59";
		$array2[57] = "lea1010digitador60";
		$array2[58] = "lea1010digitador61";
		$array2[59] = "lea1010digitador62";
		$array2[60] = "lea1010digitador63";
		$array2[61] = "lea1010digitador64";
		$array2[62] = "lea1010digitador65";
		$array2[63] = "lea1010digitador66";
		$array2[64] = "lea1010digitador67";
		$array2[65] = "lea1010digitador68";
		$array2[66] = "lea1010digitador69";
		$array2[67] = "lea1010digitador70";
		$array2[68] = "lea1010digitador71";
		$array2[69] = "lea1010digitador72";
		$array2[70] = "lea1010digitador73";
		$array2[71] = "lea1010digitador74";
		$array2[72] = "lea1010digitador75";
		$array2[73] = "lea1010digitador76";
		$array2[74] = "lea1010digitador77";
		$array2[75] = "lea1010digitador78";
		$array2[76] = "lea1010digitador79";
		$array2[77] = "lea1010digitador80";
		$array2[78] = "lea1010digitador81";
		$array2[79] = "lea1010digitador82";
		$array2[80] = "lea1010digitador83";
		$array2[81] = "lea1010digitador84";
		$array2[82] = "lea1010digitador85";
		$array2[83] = "lea1010digitador86";
		$array2[84] = "lea1010digitador87";
		$array2[85] = "lea1010digitador88";
		$array2[86] = "lea1010digitador89";
		$array2[87] = "lea1010digitador90";
		$array2[88] = "lea1010digitador91";
		$array2[89] = "lea1010digitador92";
		$array2[90] = "lea1010digitador93";
		$array2[91] = "lea1010digitador94";
		$array2[92] = "lea1010digitador95";
		$array2[93] = "lea1010digitador96";
		$array2[94] = "lea1010digitador97";
		$array2[95] = "lea1010digitador98";
		$array2[96] = "lea1010digitador99";
		$array2[97] = "lea1010digitador100";
		$array2[98] = "lea1010digitador101";
		$array2[99] = "lea1010digitador102";
		$array2[100] = "lea1010digitador103";

		
		for ($i=0; $i<count($array); $i++){
			$contrasena = $array[$i];
			$password = sha1($contrasena);
			$usuario = $array2[$i];
			$clave = $this->encode($password, $usuario);
			echo "<tr>";
			echo "<td>".$contrasena."</td>";
			echo "<td>".$usuario."</td>";
			echo "<td>".$clave."</td>";
			echo "</tr>";
		}
		echo "</table>";		
	}
	
	//Genera clave lea
	public static function encode($password, $user) {
        $hashClave = hash('sha512', $password . strtolower($user));
        return $hashClave;
    }
	
}

/* End of file welcome.php */
/* Location: ./application/controllers/welcome.php */