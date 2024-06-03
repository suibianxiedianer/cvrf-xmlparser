#![cfg_attr(
    debug_assertions,
    allow(dead_code, unused_imports, unused_variables, unused_mut)
)]
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone,  Serialize, Deserialize)]
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
}

#[derive(Debug, Clone,  Serialize, Deserialize)]
struct Publisher;

impl Publisher {
    pub fn new() -> Self {
        Publisher
    }
}

#[derive(Debug, Clone,  Serialize, Deserialize)]
struct DocumentTracking;

impl DocumentTracking {
    pub fn new() -> Self {
        DocumentTracking
    }
}

#[derive(Debug, Clone,  Serialize, Deserialize)]
struct Note;

impl Note {
    pub fn new() -> Self {
        Note
    }
}

#[derive(Debug, Clone,  Serialize, Deserialize)]
struct Reference;

impl Reference {
    pub fn new() -> Self {
        Reference
    }
}

#[derive(Debug, Clone,  Serialize, Deserialize)]
struct ProductTree;

impl ProductTree {
    pub fn new() -> Self {
        ProductTree
    }
}

#[derive(Debug, Clone,  Serialize, Deserialize)]
struct Vulnerability;

impl Vulnerability {
    pub fn new() -> Self {
        Vulnerability
    }
}
