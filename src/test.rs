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

    // tracking
    let id = "openEuler-SA-2024-1488";
    let status = "Final";
    let version = "1.0";
    let number = "1.0";
    let date = "2024-04-19";
    let description = "Initial";
    let engine = "openEuler SA Tool V1.0";
    assert_eq!(cvrf.documenttracking.identification.id, id);
    assert_eq!(cvrf.documenttracking.status, status);
    assert_eq!(cvrf.documenttracking.version, version);
    assert_eq!(cvrf.documenttracking.revisionhistory[0].number, number);
    assert_eq!(cvrf.documenttracking.revisionhistory[0].date, date);
    assert_eq!(
        cvrf.documenttracking.revisionhistory[0].description,
        description
    );
    assert_eq!(cvrf.documenttracking.initialreleasedate, date);
    assert_eq!(cvrf.documenttracking.currentreleasedate, date);
    assert_eq!(cvrf.documenttracking.generator.engine, engine);
    assert_eq!(cvrf.documenttracking.generator.date, date);
}
