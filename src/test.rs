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

    // notes
    let note_title = "Synopsis";
    let note_type = "General";
    let note_ordinal = "1";
    let note_content =  "An update for golang is now available for openEuler-20.03-LTS-SP1,openEuler-20.03-LTS-SP4,openEuler-22.03-LTS,openEuler-22.03-LTS-SP1,openEuler-22.03-LTS-SP2 and openEuler-22.03-LTS-SP3.";
    assert_eq!(cvrf.documentnotes.len(), 6);
    assert_eq!(cvrf.documentnotes[0].title, note_title);
    assert_eq!(cvrf.documentnotes[0].r#type, note_type);
    assert_eq!(cvrf.documentnotes[0].ordinal, note_ordinal);
    assert_eq!(cvrf.documentnotes[1].content, note_content);

    // references
    let reference_type = "openEuler CVE";
    let reference_url = "https://www.openeuler.org/en/security/cve/detail.html?id=CVE-2023-45288";
    assert_eq!(cvrf.documentreferences.len(), 3);
    assert_eq!(cvrf.documentreferences[1].r#type, reference_type);
    assert_eq!(cvrf.documentreferences[1].r#url, reference_url);

    // producttree
    let producttree_productid = "openEuler-22.03-LTS";
    let producttree_cep = "cpe:/a:openEuler:openEuler:22.03-LTS";
    let producttree_content = "openEuler-22.03-LTS";
    assert_eq!(cvrf.producttree.products.len(), 6);
    assert_eq!(
        cvrf.producttree.products[2].productid,
        producttree_productid
    );
    assert_eq!(cvrf.producttree.products[2].cpe, producttree_cep);
    assert_eq!(cvrf.producttree.products[2].content, producttree_content);
    let producttree_src = "src";
    let producttree_src_productid = "golang-1.17.3-32";
    let producttree_src_cep = "cpe:/a:openEuler:openEuler:22.03-LTS";
    let producttree_src_content = "golang-1.17.3-32.oe2203.src.rpm";
    assert_eq!(cvrf.producttree.packages.len(), 4);
    assert_eq!(
        cvrf.producttree.packages.get(producttree_src).unwrap()[2].productid,
        producttree_src_productid
    );
    assert_eq!(
        cvrf.producttree.packages.get(producttree_src).unwrap()[2].cpe,
        producttree_src_cep
    );
    assert_eq!(
        cvrf.producttree.packages.get(producttree_src).unwrap()[2].content,
        producttree_src_content
    );

    // vulnerabilities
    let cvrf_vulner_releasedate = "2024-04-19";
    let cvrf_vulner_cve = "CVE-2023-45288";
    let cvrf_vulner_productstatues_status = "Fixed";
    let cvrf_vulner_productstatues_product = "openEuler-22.03-LTS";
    let cvrf_vulner_threat = Severity::Important;
    let cvrf_vulner_basescore = "7.5";
    let cvrf_vulner_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H";
    let cvrf_vulner_remedition_type = "Vendor Fix";
    let cvrf_vulner_remedition_descrition = "golang security update";
    let cvrf_vulner_remedition_date = "2024-04-19";
    let cvrf_vulner_remedition_url = "https://www.openeuler.org/en/security/safety-bulletin/detail.html?id=openEuler-SA-2024-1488";

    assert_eq!(cvrf.vulnerabilities[0].notes.len(), 1);
    assert_eq!(cvrf.vulnerabilities[0].releasedate, cvrf_vulner_releasedate);
    assert_eq!(cvrf.vulnerabilities[0].cve, cvrf_vulner_cve);
    assert_eq!(
        cvrf.vulnerabilities[0].productstatuses[0].status,
        cvrf_vulner_productstatues_status
    );
    assert_eq!(
        cvrf.vulnerabilities[0].productstatuses[0].products[2],
        cvrf_vulner_productstatues_product
    );
    assert_eq!(cvrf.vulnerabilities[0].threats[0].description, cvrf_vulner_threat);
    assert_eq!(
        cvrf.vulnerabilities[0].cvssscoresets[0].basescore,
        cvrf_vulner_basescore
    );
    assert_eq!(
        cvrf.vulnerabilities[0].cvssscoresets[0].vector,
        cvrf_vulner_vector
    );
    assert_eq!(
        cvrf.vulnerabilities[0].remediations[0].r#type,
        cvrf_vulner_remedition_type
    );
    assert_eq!(
        cvrf.vulnerabilities[0].remediations[0].description,
        cvrf_vulner_remedition_descrition
    );
    assert_eq!(
        cvrf.vulnerabilities[0].remediations[0].date,
        cvrf_vulner_remedition_date
    );
    assert_eq!(
        cvrf.vulnerabilities[0].remediations[0].url,
        cvrf_vulner_remedition_url
    );
}
