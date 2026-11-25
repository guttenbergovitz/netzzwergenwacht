// Serialised into the main frame's isolated evaluation world by the CDP harness.
function collectRenderedContent() {
  const maxNodes = 16_384;
  const maxDepth = 64;
  const maxBlocks = 256;
  const maxTextUnits = 512;
  const limits = { nodes: false, depth: false, blocks: false };
  const body = document.body;
  if (!body) return null;

  const tags = new Map([
    ['p', 'paragraph'], ['main', 'main'], ['nav', 'navigation'], ['header', 'header'],
    ['footer', 'footer'], ['aside', 'aside'], ['section', 'section'], ['article', 'article'],
  ]);
  const roles = new Map([
    ['main', 'main'], ['navigation', 'navigation'], ['banner', 'header'],
    ['contentinfo', 'footer'], ['complementary', 'aside'], ['region', 'section'],
  ]);
  const excluded = new Set([
    'script', 'style', 'template', 'noscript', 'input', 'textarea', 'select', 'iframe',
  ]);
  const blocks = [];
  let visited = 0;

  function suppressesSubtree(style) {
    return style.display === 'none' || style.contentVisibility === 'hidden' || style.opacity === '0';
  }

  function markBoundary(link) {
    for (let current = link; current !== null; current = current.parent) {
      if (current.block.visible_text !== '') current.separator = true;
    }
  }

  function appendText(link, text) {
    // Bound the normalisation work even for a single enormous text node.
    const rawLimit = 2_048;
    const clipped = text.length > rawLimit;
    const raw = clipped ? text.slice(0, rawLimit).replace(/[\uD800-\uDBFF]$/, '') : text;
    const normalised = raw.toWellFormed().replace(/\s+/g, ' ');
    for (let current = link; current !== null; current = current.parent) {
      const block = current.block;
      if (clipped) block.text_truncated = true;
      if (block.text_truncated && block.visible_text.length >= maxTextUnits - 1) continue;
      const previous = block.visible_text;
      const hasSpace = previous.endsWith(' ');
      const prefix = previous === '' || hasSpace || current.separator ? normalised.trimStart() : normalised;
      if (prefix === '') continue;
      const separator = current.separator && !hasSpace ? ' ' : '';
      const remaining = maxTextUnits - previous.length - separator.length;
      if (prefix.length > remaining) block.text_truncated = true;
      if (remaining > 0) {
        const excerpt = prefix.slice(0, remaining).replace(/[\uD800-\uDBFF]$/, '');
        if (excerpt !== '') block.visible_text += separator + excerpt;
      }
      current.separator = false;
    }
  }

  const stack = [{
    node: body, depth: 0, parentBlock: null,
    suppressed: suppressesSubtree(getComputedStyle(document.documentElement)),
    visible: false,
  }];
  while (stack.length > 0) {
    const entry = stack.pop();
    if (entry.boundary !== undefined) {
      markBoundary(entry.boundary);
      continue;
    }
    if (visited === maxNodes) {
      limits.nodes = true;
      break;
    }
    const { node, depth } = entry;
    visited += 1;
    if (node !== body && node.nextSibling) stack.push({ ...entry, node: node.nextSibling });
    if (node.nodeType === Node.TEXT_NODE) {
      if (entry.visible && entry.parentBlock !== null) appendText(entry.parentBlock, node.data);
      continue;
    }
    if (node.nodeType !== Node.ELEMENT_NODE || excluded.has(node.localName) || node.isContentEditable) {
      continue;
    }
    const style = getComputedStyle(node);
    const suppressed = entry.suppressed || suppressesSubtree(style);
    const visible = !suppressed && style.visibility === 'visible';
    const kind = roles.get(node.getAttribute('role')) || tags.get(node.localName);
    const boundary = visible && (kind !== undefined && kind !== "paragraph"
      || node.localName === "p" || node.localName === "br"
      || ["block", "flex", "grid", "list-item", "table-cell"].includes(style.display));
    if (boundary) {
      markBoundary(entry.parentBlock);
      stack.push({ boundary: entry.parentBlock });
    }
    let parentBlock = entry.parentBlock;
    if (kind !== undefined) {
      if (blocks.length === maxBlocks) {
        limits.blocks = true;
      } else {
        const block = {
          node: visited, kind, visibility: visible ? 'visible' : 'hidden',
          visible_text: '', text_truncated: false,
        };
        blocks.push(block);
        parentBlock = { block, parent: parentBlock, separator: false };
      }
    }
    if (node.firstChild) {
      if (depth === maxDepth) limits.depth = true;
      else {
        const mask = style.getPropertyValue("-webkit-text-security");
        stack.push({
          node: node.firstChild, depth: depth + 1, parentBlock, suppressed,
          visible: visible && (mask === "" || mask === "none"),
        });
      }
    }
  }

  for (const block of blocks) block.visible_text = block.visible_text.replace(/\s+/g, ' ').trim();
  return {
    viewport_width: window.innerWidth,
    viewport_height: window.innerHeight,
    blocks,
    limits,
  };
}
