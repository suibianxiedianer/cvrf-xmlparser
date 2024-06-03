use crate::*;

#[test]
fn cvrf_works() {
    let mut cvrf = CVRF::new();
    let _ = cvrf.load_xml("test/cvrf-openEuler-SA-2024-1488.xml");

    let d_title = "An update for golang is now available for openEuler-20.03-LTS-SP1,openEuler-20.03-LTS-SP4,openEuler-22.03-LTS,openEuler-22.03-LTS-SP1,openEuler-22.03-LTS-SP2 and openEuler-22.03-LTS-SP3";
    let d_type = "Security Advisory";
    assert_eq!(cvrf.documenttitle, d_title);
    assert_eq!(cvrf.documenttype, d_type);

    // publisher
    let contactdetails = "openeuler-security@openeuler.org";
    let issuingauthority = "openEuler security committee";
    assert_eq!(cvrf.documentpublisher.contactdetails, contactdetails);
    assert_eq!(cvrf.documentpublisher.issuingauthority, issuingauthority);
}
