# Perl script to parse the output of the security dump-keychain -d command

#Export a keychain (ie login.keychain)
# run "security dump-keychain -d login.keychain > login.keychain.output"
# Usage: perl keychain_parser.pl login.keychain.output

#To do 
# Add in option to perform the entire process in one go
# Add in option to skip passwords that are longer than a set length or start with 0x


use strict;

my $input = shift;
my $currClass;
open(FH,"<",$input) || die "Could not open $input: $!\n";

#assume the first line contains the keychain name
my $line = <FH>;
$line =~ s/keychain: //g;
print "Printing keychain information for $line-------------------------------------------------------------------------------\n";

while ($line = <FH>){
	$currClass = $1 if $line =~ "^class: (.*)";
	
	#lines to skip
	next if $line =~ /=\<NULL\>/;
	next if $line =~ /keychain: /;
	next if $line =~ /\"atyp\"\<blob\>=.*/;
	next if $line =~ /\"crtr\"<uint32\>=\"aapl\"/;
	next if $line =~ /\"port\"\<uint32\>=/;
	next if $line =~ /\"ptcl\"\<uint32\>=/;
	next if $line =~ /\"sdmn\"\<blob\>=\"Locked\"/;
	next if $line =~ /\"icmt\"<blob\>=.*/;
	next if $line =~ /\"crtr\"\<uint32\>=.*/;
	next if $line =~ /attributes/;

	#Skip certain classes
	next if $currClass =~ "0x80001000";
	next if $currClass =~ "0x80001001";
	next if $currClass =~ "ashp";
	next if $currClass =~ "0x0000000F";
	next if $currClass =~ "0x00000010";

	
	$line =~ s/0x00000007 <blob>=/Account Type:\t\t/;
	$line =~ s/\"acct\"\<blob\>=/Account Name:\t\t/;
	$line =~ s/\"cdat\"\<timedate\>=.* \"(....)(..)(..)(..)(..)(..)(.*)\"/Created Date:\t\t$1:$2:$3 $4:$5:$6 $7/;
	$line =~ s/\"mdat\"\<timedate\>=.* \"(....)(..)(..)(..)(..)(..)(.*)\"/Modified Date:\t\t$1:$2:$3 $4:$5:$6 $7/;	
	$line =~ s/\"srvr\"\<blob\>=/Server:\t\t\t\t/;
	$line =~ s/\"path\"\<blob\>=/Path:\t\t\t\t/;
	$line =~ s/\"desc\"\<blob\>=/Description:\t\t/;
	$line =~ s/\"svce\"\<blob\>=/Service:\t\t\t/;
	


	#Dont print the class
	next if $line =~ "^class:";
	
	#Removes the Data: line and inserts Password at the beginning of the following line
	if ($line =~ "data:"){
		chomp $line;
		my $password = <FH>;
		$line = "Password: \t\t\t".$password."\n"; 
	}
	
	#replace all of the spacing at the beginning of the line
	$line =~ s/^    //;
	print $line;
	#print "$currClass\t$line";
	}
close(FH);