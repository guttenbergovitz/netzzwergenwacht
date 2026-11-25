use super::*;

#[test]
fn respects_language_inheritance_and_source_hidden_content() {
    let document = Html::parse_document(
        "<html lang=pl><main lang=de><p lang=en>Hello\n <em>world</em></p>
         <p><span hidden>Secret</span> Guten Tag</p></main><aside>Links</aside>",
    );
    let content = ContentSegmentation::extract(&document);
    assert_eq!(content.paragraphs[0].text, "Hello world");
    assert_eq!(content.paragraphs[0].language(), Some("en"));
    assert_eq!(content.paragraphs[1].language(), Some("de"));
    assert_eq!(content.paragraphs[1].text, "Guten Tag");
    assert_eq!(content.main_words.unwrap().outside_main, 1);
}

#[test]
fn joins_inline_words_and_preserves_line_boundaries() {
    let input = "<nav>two words</nav><main><p>inter<em>national</em><br>shipping</p></main>";
    let content = ContentSegmentation::extract(&Html::parse_document(input));
    assert_eq!(content.paragraphs[0].text, "international shipping");
    assert_eq!(
        content.main_words,
        Some(MainContentWords {
            outside_main: 2,
            total: 4
        })
    );
}

#[test]
fn caps_language_attributes_and_tree_depth() {
    let long = format!(
        "<main lang='{}'><p>Text</p></main>",
        "x".repeat(MAX_LANGUAGE_BYTES + 1)
    );
    let content = ContentSegmentation::extract(&Html::parse_document(&long));
    assert!(content.paragraphs_truncated);
    assert_eq!(content.paragraphs.len(), 0);

    let nested = format!(
        "{}<p>Deep</p>{}",
        "<div>".repeat(MAX_SOURCE_DEPTH),
        "</div>".repeat(MAX_SOURCE_DEPTH)
    );
    let content = ContentSegmentation::extract(&Html::parse_document(&nested));
    assert!(content.tree_limit_reached);
    assert!(content.main_words.is_none());
}

#[test]
fn marks_limits_and_ambiguous_main_regions() {
    let input = format!(
        "<main><p>{}</p></main><div role=main>Other</div>",
        "é".repeat(MAX_BLOCK_BYTES),
    );
    let content = ContentSegmentation::extract(&Html::parse_document(&input));
    assert!(content.paragraphs_truncated);
    assert_eq!(content.paragraphs.len(), 0);
    assert!(content.main_words.is_none());
}
