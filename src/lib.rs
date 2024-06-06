#![cfg_attr(
    debug_assertions,
    allow(dead_code, unused_imports, unused_variables, unused_mut)
)]
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader};

use serde::{Deserialize, Serialize};
use tracing::{debug, error, instrument, trace};
use xml::reader::{EventReader, XmlEvent};

#[cfg(test)]
mod test;

#[allow(dead_code)]
struct XmlReader {
    // an iterator for XmlEvent
    events: EventReader<BufReader<File>>,

    // the depth in xml
    depth: usize,
}

impl XmlReader {
    pub fn new(file: File) -> Self {
        let buffer = BufReader::new(file);
        let events = EventReader::new(buffer);

        XmlReader { events, depth: 0 }
    }

    // pull next stream from xml, set the depth as well.
    pub fn next(&mut self) -> Result<xml::reader::XmlEvent, xml::reader::Error> {
        let event = self.events.next();
        match event {
            Ok(XmlEvent::StartElement { .. }) => {
                self.depth += 1;
            }
            Ok(XmlEvent::EndElement { .. }) => {
                self.depth -= 1;
            }
            _ => {}
        }

        event
    }

    /// 若下一个字段是 StrartElement，则返回其 name , 若为其它元素，则返回一个空字符串，类型为
    /// Option<String>。当其所在深度小于指定值时，返回 None。
    #[instrument(skip(self, depth))]
    pub fn next_start_name_under_depth(&mut self, depth: usize) -> Option<String> {
        match self.next() {
            Ok(XmlEvent::StartElement { name, .. }) => {
                debug!("Find StartElement named: {}", name.local_name);
                Some(name.local_name.clone())
            }
            Ok(XmlEvent::EndElement { .. }) => {
                if self.depth > depth {
                    Some(String::new())
                } else {
                    None
                }
            }
            Err(e) => {
                error!("XmlReader Error: {e}");
                None
            }
            _ => Some(String::new()),
        }
    }

    /// 向下读取一个 Characters 类型的值，并忽略其它除 EndDocument 和
    /// 错误外的所有结果（此时返回空字符串）。
    #[instrument(skip(self))]
    pub fn next_characters(&mut self) -> String {
        loop {
            match self.next() {
                Ok(XmlEvent::Characters(data)) => {
                    trace!(characters = ?data);
                    return data.into();
                }
                Ok(XmlEvent::EndDocument) => {
                    error!("End of the xml, that shouldn't happen...");
                    return "".to_string();
                }
                Ok(_) => {}
                Err(e) => {
                    error!("XmlReader error: {e}");
                    return "".to_string();
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CVRF {
    // <DocumentTitle xml:lang="en">
    pub documenttitle: String,

    // <DocumentType>
    pub documenttype: String,

    // <DocumentPublisher Type="Vendor">
    pub documentpublisher: Publisher,

    // <DocumentTracking>
    pub documenttracking: DocumentTracking,

    // <DocumentNotes>
    pub documentnotes: Vec<Note>,

    // <DocumentReferences>
    pub documentreferences: Vec<Reference>,

    // <ProductTree xmlns="http://www.icasi.org/CVRF/schema/prod/1.1">
    pub producttree: ProductTree,

    // <Vulnerability xmlns="http://www.icasi.org/CVRF/schema/vuln/1.1" Ordinal="1">
    pub vulnerability: Vulnerability,
}

impl CVRF {
    // 新建一个空 CVRF
    #[allow(dead_code)]
    pub fn new() -> Self {
        CVRF {
            documenttitle: String::new(),
            documenttype: String::new(),
            documentpublisher: Publisher::new(),
            documenttracking: DocumentTracking::new(),
            documentnotes: vec![],
            documentreferences: vec![],
            producttree: ProductTree::new(),
            vulnerability: Vulnerability::new(),
        }
    }

    #[instrument(skip(self))]
    pub fn load_xml(&mut self, xmlfile: &str) -> io::Result<()> {
        let file = File::open(xmlfile)?;
        let mut source = XmlReader::new(file);
        let xmlreader = &mut source;

        loop {
            let event = xmlreader.next();
            if xmlreader.depth != 2 {
                if event == Ok(XmlEvent::EndDocument) {
                    trace!("End of the xml, break...");
                    break;
                }
                continue;
            }

            // 这里只处理深度为 2 的子 xml 块
            match event {
                Ok(XmlEvent::StartElement { ref name, .. }) => match name.local_name.as_str() {
                    "DocumentTitle" => self.documenttitle = xmlreader.next_characters(),
                    "DocumentType" => self.documenttype = xmlreader.next_characters(),
                    "DocumentPublisher" => self.documentpublisher.load_from_xmlreader(xmlreader),
                    "DocumentTracking" => self.documenttracking.load_from_xmlreader(xmlreader),
                    "DocumentNotes" => self.handle_notes(xmlreader),
                    _ => {}
                },
                Err(e) => {
                    error!("XmlReader error: {e}");
                    break;
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn handle_notes(&mut self, xmlreader: &mut XmlReader) {
        loop {
            let mut note = Note::new();
            note.load_from_xmlreader(xmlreader);

            if xmlreader.depth < 2 {
                break;
            }
            self.documentnotes.push(note)
        }
    }
}

// depth = 2
// <DocumentPublisher Type="Vendor">
//   <ContactDetails>openeuler-security@openeuler.org</ContactDetails>
//   <IssuingAuthority>openEuler security committee</IssuingAuthority>
// </DocumentPublisher>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Publisher {
    // <ContactDetails>
    pub contactdetails: String,

    // <IssuingAuthority>
    pub issuingauthority: String,
}

impl Publisher {
    pub fn new() -> Self {
        Publisher {
            contactdetails: String::new(),
            issuingauthority: String::new(),
        }
    }

    #[instrument(skip(self, xmlreader))]
    fn load_from_xmlreader(&mut self, xmlreader: &mut XmlReader) {
        loop {
            let key = if let Some(key) = xmlreader.next_start_name_under_depth(1) {
                key
            } else {
                break;
            };

            match key.as_str() {
                "ContactDetails" => self.contactdetails = xmlreader.next_characters(),
                "IssuingAuthority" => self.issuingauthority = xmlreader.next_characters(),
                _ => {}
            }
        }
    }
}

// depth = 2
// <DocumentTracking>
//   <Identification>
//     <ID>openEuler-SA-2024-1488</ID>
//   </Identification>
//   <Status>Final</Status>
//   <Version>1.0</Version>
//   <RevisionHistory>
//     <Revision>
//       <Number>1.0</Number>
//       <Date>2024-04-19</Date>
//       <Description>Initial</Description>
//     </Revision>
//   </RevisionHistory>
//   <InitialReleaseDate>2024-04-19</InitialReleaseDate>
//   <CurrentReleaseDate>2024-04-19</CurrentReleaseDate>
//   <Generator>
//     <Engine>openEuler SA Tool V1.0</Engine>
//     <Date>2024-04-19</Date>
//   </Generator>
// </DocumentTracking>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentTracking {
    // <Identification>
    pub identification: Identification,

    // <Status>
    pub status: String,

    // <Version>
    pub version: String,

    // <RevisionHistory>
    pub revisionhistory: Vec<Revision>,

    // <InitialReleaseDate>
    pub initialreleasedate: String,

    // <CurrentReleaseDate>
    pub currentreleasedate: String,

    // <Generator>
    pub generator: Generator,
}

impl DocumentTracking {
    pub fn new() -> Self {
        DocumentTracking {
            identification: Identification::new(),
            status: String::new(),
            version: String::new(),
            revisionhistory: Vec::new(),
            initialreleasedate: String::new(),
            currentreleasedate: String::new(),
            generator: Generator::new(),
        }
    }

    #[instrument(skip(self, xmlreader))]
    fn load_from_xmlreader(&mut self, xmlreader: &mut XmlReader) {
        loop {
            let key = if let Some(key) = xmlreader.next_start_name_under_depth(1) {
                key
            } else {
                break;
            };

            match key.as_str() {
                "Identification" => self.identification.load_from_xmlreader(xmlreader),
                "Status" => self.status = xmlreader.next_characters(),
                "Version" => self.version = xmlreader.next_characters(),
                "RevisionHistory" => self.handle_revisionhistory(xmlreader),
                "InitialReleaseDate" => self.initialreleasedate = xmlreader.next_characters(),
                "CurrentReleaseDate" => self.currentreleasedate = xmlreader.next_characters(),
                "Generator" => self.generator.load_from_xmlreader(xmlreader),
                _ => {}
            }
        }
    }

    #[instrument(skip(self, xmlreader))]
    fn handle_revisionhistory(&mut self, xmlreader: &mut XmlReader) {
        loop {
            let mut revision = Revision::new();
            revision.load_from_xmlreader(xmlreader);
            // 所有 revision 读取完毕
            if xmlreader.depth < 3 {
                trace!("RevisionHistory read to end.");
                break;
            }
            trace!("RevisionHistory loading revison...");
            self.revisionhistory.push(revision);
        }
    }
}

// depth = 3
// <Identification>
//   <ID>openEuler-SA-2024-1488</ID>
// </Identification>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identification {
    // <ID>
    pub id: String,
}

impl Identification {
    pub fn new() -> Self {
        Identification { id: String::new() }
    }

    #[instrument(skip(self, xmlreader))]
    fn load_from_xmlreader(&mut self, xmlreader: &mut XmlReader) {
        self.id = xmlreader.next_characters();
    }
}

// depth = 4
// <Revision>
//   <Number>1.0</Number>
//   <Date>2024-04-19</Date>
//   <Description>Initial</Description>
// </Revision>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revision {
    // <Number>
    pub number: String,

    // <Date>
    pub date: String,

    // <Description>
    pub description: String,
}

impl Revision {
    pub fn new() -> Self {
        Revision {
            number: String::new(),
            date: String::new(),
            description: String::new(),
        }
    }

    #[instrument(skip(self, xmlreader))]
    fn load_from_xmlreader(&mut self, xmlreader: &mut XmlReader) {
        loop {
            let key = if let Some(key) = xmlreader.next_start_name_under_depth(3) {
                key
            } else {
                break;
            };

            match key.as_str() {
                "Number" => self.number = xmlreader.next_characters(),
                "Date" => self.date = xmlreader.next_characters(),
                "Description" => self.description = xmlreader.next_characters(),
                _ => {}
            }
        }
    }
}

// depth = 3
// <Generator>
//   <Engine>openEuler SA Tool V1.0</Engine>
//   <Date>2024-04-19</Date>
// </Generator>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Generator {
    // <Engine>
    pub engine: String,

    // <Date>
    pub date: String,
}

impl Generator {
    pub fn new() -> Self {
        Generator {
            engine: String::new(),
            date: String::new(),
        }
    }

    #[instrument(skip(self, xmlreader))]
    fn load_from_xmlreader(&mut self, xmlreader: &mut XmlReader) {
        loop {
            let key = if let Some(key) = xmlreader.next_start_name_under_depth(1) {
                key
            } else {
                break;
            };

            match key.as_str() {
                "Engine" => self.engine = xmlreader.next_characters(),
                "Date" => self.date = xmlreader.next_characters(),
                _ => {}
            }
        }
    }
}

// <Note Title="Affected Component" Type="General" Ordinal="6" xml:lang="en">
//   kernel
// </Note>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    // Title: main key
    pub title: String,

    // Type may useless
    pub r#type: String,

    // Ordinal may useless
    pub ordinal: String,

    // Content: values
    pub content: String,
}

impl Note {
    pub fn new() -> Self {
        Note {
            title: String::new(),
            r#type: String::new(),
            ordinal: String::new(),
            content: String::new(),
        }
    }

    fn load_from_xmlreader(&mut self, xmlreader: &mut XmlReader) {
        unimplemented!();
    }
}

// depth = 3
// <Reference Type="Self">
//   <URL>
//     https://www.openeuler.org/en/security/safety-bulletin/detail.html?id=openEuler-SA-2024-1488
//   </URL>
// </Reference>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub r#type: String,
    pub url: String,
}

impl Reference {
    pub fn new() -> Self {
        Reference {
            r#type: String::new(),
            url: String::new(),
        }
    }
}

// depth = 2
// <ProductTree xmlns="http://www.icasi.org/CVRF/schema/prod/1.1">
//   <Branch Type="Product Name" Name="openEuler">
//     <FullProductName ProductID="openEuler-22.03-LTS" CPE="cpe:/a:openEuler:openEuler:22.03-LTS">
//       openEuler-22.03-LTS
//     </FullProductName>
//     <FullProductName ProductID="openEuler-22.03-LTS-SP1" CPE="cpe:/a:openEuler:openEuler:22.03-LTS-SP1">
//       openEuler-22.03-LTS-SP1
//     </FullProductName>
//   </Branch>
//
//   <Branch Type="Package Arch" Name="src">
//     <FullProductName ProductID="golang-1.17.3-32" CPE="cpe:/a:openEuler:openEuler:22.03-LTS">
//       golang-1.17.3-32.oe2203.src.rpm
//     </FullProductName>
//     <FullProductName ProductID="golang-1.17.3-32" CPE="cpe:/a:openEuler:openEuler:22.03-LTS-SP1">
//       golang-1.17.3-32.oe2203sp1.src.rpm
//     </FullProductName>
//   Branch>
//   <Branch Type="Package Arch" Name="aarch64">...</Branch>
// </ProductTree>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductTree {
    // <Branch Type="Product Name" Name="openEuler">
    // type `Product Name` only have one name: openEuler
    pub products: Vec<Product>,

    // <Branch Type="Package Arch" Name="src">
    // type `Product Arch` may have lots of name: src/aarch64/x86_64/noarch and so on.
    pub packages: HashMap<String, Vec<Product>>,
}

impl ProductTree {
    pub fn new() -> Self {
        ProductTree {
            products: Vec::new(),
            packages: HashMap::new(),
        }
    }
}

// depth = 4
// <FullProductName ProductID="openEuler-22.03-LTS" CPE="cpe:/a:openEuler:openEuler:22.03-LTS">
//   openEuler-22.03-LTS
// </FullProductName>
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Product {
    // attr ProductID
    pub productid: String,

    // attr CPE
    pub cpe: String,

    // content
    pub content: String,
}

impl Product {
    pub fn new() -> Self {
        Self {
            productid: String::new(),
            cpe: String::new(),
            content: String::new(),
        }
    }
}

// depth = 2
// <Vulnerability Ordinal="1" xmlns="http://www.icasi.org/CVRF/schema/vuln/1.1">
//   <Notes>...</Notes>
//   <ReleaseDate>2024-04-19</ReleaseDate>
//   <CVE>CVE-2023-45288</CVE>
//   <ProductStatuses>...</ProductStatuses>
//   <Threats>...</Threats>
//   <CVSSScoreSets>...</CVSSScoreSets>
//   <Remediations>...</Remediations>
// </Vulnerability>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    // <Notes>...</Notes>
    pub notes: Vec<Note>,

    // <ReleaseDate>
    pub releasedate: String,

    // <CVE>
    pub cve: String,

    // <ProductStatuses>...</ProductStatuses>
    pub productstatuses: Vec<ProductStatus>,

    // <Threats>...</Threats>
    pub threats: Vec<Threat>,

    // <CVSSScoreSets>...</CVSSScoreSets>
    pub cvssscoresets: Vec<ScoreSet>,

    // <Remediations>...</Remediations>
    pub remediations: Vec<Remediation>,
}

impl Vulnerability {
    pub fn new() -> Self {
        Vulnerability {
            notes: Vec::new(),
            releasedate: String::new(),
            cve: String::new(),
            productstatuses: Vec::new(),
            threats: Vec::new(),
            cvssscoresets: Vec::new(),
            remediations: Vec::new(),
        }
    }
}

// depth = 4
// <Status Type="Fixed">
//   <ProductID>openEuler-22.03-LTS</ProductID>
//   <ProductID>openEuler-22.03-LTS-SP1</ProductID>
// </Status>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductStatus {
    // status Type
    pub status: String,

    // <ProductID>s
    pub products: Vec<String>,
}

impl ProductStatus {
    pub fn new() -> Self {
        ProductStatus {
            status: String::new(),
            products: Vec::new(),
        }
    }
}

// depth = 4
// <Threat Type="Impact">
//   <Description>High</Description>
// </Threat>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    // Type Impact or more?
    pub r#type: String,

    // As threat level
    pub description: String,
}

impl Threat {
    pub fn new() -> Self {
        Threat {
            r#type: String::new(),
            description: String::new(),
        }
    }
}

// depth = 4
// <ScoreSet>
//   <BaseScore>7.5</BaseScore>
//   <Vector>AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</Vector>
// </ScoreSet>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreSet {
    // score point
    pub basescore: String,

    // keep it
    pub vector: String,
}

impl ScoreSet {
    pub fn new() -> Self {
        ScoreSet {
            basescore: String::new(),
            vector: String::new(),
        }
    }
}

// depth = 4
// <Remediation Type="Vendor Fix">
//   <Description>golang security update</Description>
//   <DATE>2024-04-19</DATE>
//   <URL>
//     https://www.openeuler.org/en/security/safety-bulletin/detail.html?id=openEuler-SA-2024-1488
//   </URL>
// </Remediation>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    // current type
    pub r#type: String,

    // description
    pub description: String,

    // release date
    pub date: String,

    // openEuler SA URL
    pub url: String,
}

impl Remediation {
    pub fn new() -> Self {
        Remediation {
            r#type: String::new(),
            description: String::new(),
            date: String::new(),
            url: String::new(),
        }
    }
}
