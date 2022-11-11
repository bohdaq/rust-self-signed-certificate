use openssl::pkey::PKey;
use openssl::rsa::Rsa;

fn main() {
    println!("Application to generate self signed certificate");
    let (encryption_params, _decryption_params) = crypto_ext::asymmetric::encryption::setup(Some("/")).unwrap();

    let rsa_public = Rsa::public_key_from_pem(encryption_params.rsa_public_key_pem.as_bytes()).unwrap();

    let mut cert_name = openssl::x509::X509NameBuilder::new().unwrap();
    cert_name.append_entry_by_text("C", "UA").unwrap();
    cert_name.append_entry_by_text("O", "Organization name").unwrap();
    cert_name.append_entry_by_text("CN", "example.com").unwrap();
    let cert_name = cert_name.build();

    let mut cert = openssl::x509::X509::builder().unwrap();

    let pkey = PKey::from_rsa(rsa_public).unwrap();

    let pkey_ref = pkey.as_ref();

    cert.set_pubkey(pkey_ref).unwrap();

    cert.set_subject_name(&cert_name).unwrap();

    let cert = cert.build();

    let cert = cert.to_pem().unwrap();

    let as_string = String::from_utf8(cert).unwrap();

    println!("certificate: \n {}", as_string);
}
