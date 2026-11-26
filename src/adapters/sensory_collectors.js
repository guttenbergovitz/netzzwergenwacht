// Bounded sensory collectors for Operation Aufrüstung IV (Waves IV-B through IV-H).
// Evaluates inside an isolated or page execution context and post-processes
// SHA-256 digests in the Node.js CDP harness so raw untrusted text or secrets
// never cross into LLM prompts or persisted inventories.

// UTF-8 byte length for retained value sizes. JavaScript string length counts
// UTF-16 code units, which understates multibyte content.
function utf8ByteLength(value) {
  if (typeof value !== 'string') return 0;
  try {
    return new TextEncoder().encode(value).length;
  } catch {
    return 0;
  }
}

function hostMatchesCookieDomain(host, domain) {
  if (!host || !domain) return false;
  const h = String(host).toLowerCase();
  const d = String(domain).toLowerCase().replace(/^\./, '');
  if (!d) return false;
  const labels = d.split('.').filter(Boolean);
  // A single-label domain only matches itself (`localhost` style hosts). Treating
  // bare public suffixes as a parent domain would misclassify every site beneath them.
  if (labels.length < 2 && d !== 'localhost') return false;
  return h === d || h.endsWith(`.${d}`);
}

function buildAxNodeInventoryFromCdp(cdpNodes, sha256HexFn) {
  if (!Array.isArray(cdpNodes)) return null;
  const MAX_RETAINED = 256;
  const interactiveRoles = new Set([
    'button', 'link', 'textbox', 'searchbox', 'combobox', 'listbox',
    'menuitem', 'menuitemcheckbox', 'menuitemradio', 'option', 'radio',
    'checkbox', 'switch', 'slider', 'spinbutton', 'tab', 'treeitem',
  ]);
  const indexById = new Map();
  const retained = [];
  for (let i = 0; i < cdpNodes.length; i += 1) {
    if (retained.length >= MAX_RETAINED) break;
    const n = cdpNodes[i];
    if (!n || typeof n !== 'object') continue;
    const nodeIndex = retained.length + 1;
    const nodeId = String(n.nodeId ?? nodeIndex).slice(0, 64);
    indexById.set(nodeId, nodeIndex);
    const roleRaw = String(n.role?.value || 'generic').toLowerCase().slice(0, 48);
    const nameRaw = typeof n.name?.value === 'string' ? n.name.value.replace(/\s+/g, ' ').trim() : '';
    const namePresent = nameRaw.length > 0;
    const nameFingerprint = namePresent ? `sha256:v1:${sha256HexFn(nameRaw)}` : null;
    let nameSource = 'none';
    if (Array.isArray(n.name?.sources) && n.name.sources.length > 0) {
      const activeSrc = n.name.sources.find((s) => s && s.value && s.value.value) || n.name.sources[0];
      const st = String(activeSrc?.type || '').toLowerCase();
      if (st === 'attribute') nameSource = 'attribute';
      else if (st === 'relatedelement') nameSource = 'related_element';
      else if (st === 'contents') nameSource = 'contents';
      else if (st === 'placeholder') nameSource = 'placeholder';
      else if (st === 'title') nameSource = 'title';
      else if (namePresent) nameSource = 'other';
    } else if (namePresent) {
      nameSource = 'contents';
    }
    const descRaw = typeof n.description?.value === 'string' ? n.description.value.trim() : '';
    const props = Array.isArray(n.properties) ? n.properties : [];
    const propMap = new Map();
    for (const p of props) {
      if (p && typeof p.name === 'string') {
        propMap.set(p.name, p.value?.value);
      }
    }
    const ignored = Boolean(n.ignored);
    let ignoredReason = null;
    if (ignored && Array.isArray(n.ignoredReasons) && n.ignoredReasons.length > 0) {
      ignoredReason = String(n.ignoredReasons[0]?.name || 'ignored').slice(0, 48);
    }
    retained.push({
      node_index: nodeIndex,
      ax_node_id: nodeId,
      _raw_parent_id: n.parentId ? String(n.parentId) : null,
      parent_index: null,
      child_count: Array.isArray(n.childIds) ? n.childIds.length : 0,
      role: roleRaw,
      name_present: namePresent,
      name_length: Array.from(nameRaw).length,
      name_fingerprint: nameFingerprint,
      name_source: nameSource,
      description_present: descRaw.length > 0,
      focusable: Boolean(propMap.get('focusable')),
      focused: Boolean(propMap.get('focused')),
      disabled: Boolean(propMap.get('disabled')),
      expanded: typeof propMap.get('expanded') === 'boolean' ? propMap.get('expanded') : null,
      selected: typeof propMap.get('selected') === 'boolean' ? propMap.get('selected') : null,
      checked: propMap.has('checked') ? String(propMap.get('checked')).slice(0, 16) : null,
      modal: typeof propMap.get('modal') === 'boolean' ? propMap.get('modal') : null,
      live_politeness: propMap.has('live') ? String(propMap.get('live')).slice(0, 24) : null,
      ignored,
      ignored_reason: ignoredReason,
      interactive: interactiveRoles.has(roleRaw) || Boolean(propMap.get('focusable')),
    });
  }
  for (const item of retained) {
    if (item._raw_parent_id && indexById.has(item._raw_parent_id)) {
      item.parent_index = indexById.get(item._raw_parent_id);
    }
    delete item._raw_parent_id;
  }
  return {
    nodes: retained,
    limits: {
      total_cdp_nodes: cdpNodes.length,
      nodes_truncated: cdpNodes.length > MAX_RETAINED,
    },
  };
}

async function collectInPageSensoryBundle() {
  const MAX_DOM_NODES = 16384;
  const MAX_DEPTH = 64;
  const MAX_INTERACTIVE = 256;
  const MAX_GEOMETRY = 128;
  const MAX_MEDIA = 128;
  const MAX_FONTS = 64;
  const MAX_LINKS = 256;
  const MAX_FORMS = 32;
  const MAX_ENTITIES = 32;
  const MAX_HREFLANG = 64;
  const MAX_STORAGE_KEYS = 128;

  const vw = Math.max(0, Math.round(window.innerWidth || document.documentElement?.clientWidth || 0));
  const vh = Math.max(0, Math.round(window.innerHeight || document.documentElement?.clientHeight || 0));
  const pageOrigin = window.location?.origin || '';
  const utf8ByteLength = (value) => {
    if (typeof value !== 'string') return 0;
    try {
      return new TextEncoder().encode(value).length;
    } catch {
      return 0;
    }
  };

  const idCounts = new Map();
  let idVisited = 0;
  const countIds = (root) => {
    const stack = [root];
    while (stack.length > 0 && idVisited < MAX_DOM_NODES) {
      const el = stack.pop();
      if (!el || el.nodeType !== 1) continue;
      idVisited += 1;
      const rawId = typeof el.id === 'string' ? el.id.trim() : '';
      if (rawId) {
        idCounts.set(rawId, (idCounts.get(rawId) || 0) + 1);
      }
      const children = el.children || [];
      for (let i = children.length - 1; i >= 0; i -= 1) {
        stack.push(children[i]);
      }
    }
  };
  if (document.documentElement) countIds(document.documentElement);

  const buildIdentity = (el, pathSegments) => {
    const rawId = typeof el?.id === 'string' ? el.id.trim() : '';
    let idObj = { status: 'absent' };
    if (rawId) {
      const count = idCounts.get(rawId) || 1;
      idObj = {
        status: count === 1 ? 'unique' : 'duplicate',
        _raw_id: rawId.slice(0, 128),
      };
    }
    return {
      path: Array.isArray(pathSegments) ? pathSegments.slice(0, MAX_DEPTH) : null,
      id: idObj,
    };
  };

  const sanitizeUrlParts = (rawHref) => {
    if (!rawHref || typeof rawHref !== 'string') return null;
    const trimmed = rawHref.trim();
    if (!trimmed) return null;
    if (trimmed.startsWith('#')) {
      return {
        origin: pageOrigin || null,
        path: window.location?.pathname || '/',
        same_origin: true,
        fragment_only: true,
      };
    }
    try {
      const parsed = new URL(trimmed, window.location.href);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return null;
      }
      return {
        origin: parsed.origin,
        path: (parsed.pathname || '/').replace(/[\x00-\x1f\x7f]/g, '').slice(0, 256),
        same_origin: parsed.origin === pageOrigin,
        fragment_only: false,
      };
    } catch {
      return null;
    }
  };

  const getAccessibleName = (el) => {
    if (!el || el.nodeType !== 1) return '';
    const ariaLabel = el.getAttribute('aria-label');
    if (ariaLabel && ariaLabel.trim()) return ariaLabel.replace(/\s+/g, ' ').trim();
    const labelledBy = el.getAttribute('aria-labelledby');
    if (labelledBy) {
      const parts = labelledBy
        .split(/\s+/)
        .map((id) => document.getElementById(id)?.innerText || '')
        .filter(Boolean);
      if (parts.length > 0) return parts.join(' ').replace(/\s+/g, ' ').trim();
    }
    if (el.tagName === 'INPUT' || el.tagName === 'SELECT' || el.tagName === 'TEXTAREA') {
      if (el.id) {
        try {
          const lbl = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
          if (lbl && lbl.innerText) return lbl.innerText.replace(/\s+/g, ' ').trim();
        } catch {}
      }
      const parentLabel = el.closest('label');
      if (parentLabel && parentLabel.innerText) {
        return parentLabel.innerText.replace(/\s+/g, ' ').trim();
      }
      const placeholder = el.getAttribute('placeholder');
      if (placeholder && placeholder.trim()) return placeholder.replace(/\s+/g, ' ').trim();
    }
    const alt = el.getAttribute('alt');
    if (alt && alt.trim()) return alt.replace(/\s+/g, ' ').trim();
    const title = el.getAttribute('title');
    if (title && title.trim()) return title.replace(/\s+/g, ' ').trim();
    const txt = (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim();
    return txt.slice(0, 512);
  };

  const isVisible = (el, style, rect) => {
    if (!style || style.display === 'none' || style.visibility === 'hidden' || style.visibility === 'collapse') {
      return false;
    }
    if (Number(style.opacity) === 0) return false;
    return rect.width > 0 && rect.height > 0;
  };

  const classifyInteractive = (el, tag, role, typeAttr, nameLower) => {
    let safety = 'read_only_ui_toggle';
    let kind = 'generic_control';
    const form = el.closest('form');
    const isSubmit =
      (tag === 'button' && (!typeAttr || typeAttr === 'submit')) ||
      (tag === 'input' && (typeAttr === 'submit' || typeAttr === 'image'));

    if (tag === 'a' && el.hasAttribute('href')) {
      const rawHref = (el.getAttribute('href') || '').trim();
      safety = rawHref.startsWith('#') ? 'read_only_ui_toggle' : 'read_only_navigation';
      if (el.hasAttribute('download')) kind = 'download_control';
      else if (el.closest('nav,[role="navigation"]')) kind = 'navigation_menu';
      else if (/next|prev|page|\b\d+\b/i.test(nameLower) && el.closest('[aria-label*="pag" i],.pagination')) {
        kind = 'pagination';
      } else if (/buy|checkout|sign up|get started|subscribe|start|register|book/i.test(nameLower)) {
        kind = 'cta';
      }
    } else if (tag === 'input' || tag === 'textarea' || tag === 'select') {
      safety = isSubmit ? 'state_changing_submission' : 'form_input';
      if (typeAttr === 'search' || role === 'searchbox' || /search/i.test(nameLower)) kind = 'search';
      else if (/lang|locale|currency|country/i.test(nameLower)) kind = 'language_selector';
      else if (/sort/i.test(nameLower)) kind = 'sort';
      else if (/filter/i.test(nameLower)) kind = 'filter';
      else if (/size|color|colour|variant|quantity|qty/i.test(nameLower)) kind = 'product_selector';
      else kind = 'form';
    } else if (isSubmit && form) {
      const method = (form.getAttribute('method') || 'get').toLowerCase();
      const hasSearch = Boolean(form.querySelector('input[type="search"],[role="searchbox"]'));
      safety = method === 'get' && hasSearch ? 'read_only_navigation' : 'state_changing_submission';
      kind = hasSearch ? 'search' : 'cta';
    } else {
      if (
        /delete|remove|buy|pay|checkout|purchase|order|submit|save|confirm|accept|allow/i.test(
          nameLower
        )
      ) {
        safety = 'state_changing_submission';
        kind = 'cta';
      } else if (role === 'tab') {
        kind = 'tabs';
      } else if (tag === 'summary' || el.hasAttribute('aria-expanded')) {
        kind = el.closest('nav,[role="navigation"]') ? 'navigation_menu' : 'accordion';
      } else if (role === 'combobox') {
        kind = 'combobox';
      } else if (el.closest('dialog,[role="dialog"],[role="alertdialog"]')) {
        kind = 'dialog';
      } else if (/search/i.test(nameLower)) {
        kind = 'search';
      } else if (/filter/i.test(nameLower)) {
        kind = 'filter';
      } else if (/sort/i.test(nameLower)) {
        kind = 'sort';
      } else if (/lang|locale|english|deutsch|polski/i.test(nameLower)) {
        kind = 'language_selector';
      } else if (/play|pause|mute|volume/i.test(nameLower)) {
        kind = 'media_player';
      } else if (/next|prev|slide|carousel/i.test(nameLower)) {
        kind = 'carousel';
      }
    }
    return { safety, kind };
  };

  const interactiveElements = [];
  let discoveredInteractive = 0;
  let interactiveTruncated = false;

  const geometryElements = [];
  let geometryTruncated = false;

  const mediaAssets = [];
  let mediaTruncated = false;

  const links = [];
  let linksTruncated = false;
  const clusterSummary = {
    internal_links: 0,
    external_links: 0,
    header_nav_links: 0,
    main_content_links: 0,
    footer_links: 0,
    empty_anchor_links: 0,
  };

  const forms = [];
  let formsTruncated = false;

  const landmarks = [];
  const aboveFoldRects = [];
  const ABOVE_FOLD_RECT_LIMIT = 64;
  let aboveFoldRectsTruncated = false;

  let externalScriptsWithoutSri = 0;
  let unsafeTargetBlankLinks = 0;
  const thirdPartyCapabilities = new Map();
  let liveRegionCount = 0;
  let ariaInvalidCount = 0;

  // Toggle candidate DOM elements for real bounded read-only interaction probing
  const readOnlyToggleCandidates = [];

  let visitedNodes = 0;
  let domTruncated = false;
  let depthTruncated = false;

  const interactiveSelector =
    'a[href],button,input:not([type="hidden"]),select,textarea,summary,[role="button"],[role="link"],[role="tab"],[role="menuitem"],[role="checkbox"],[role="switch"],[role="combobox"],[tabindex]';

  const normalizeOverflow = (val) => {
    const v = String(val || 'visible').toLowerCase();
    if (v === 'visible') return 'visible';
    if (v === 'hidden') return 'hidden';
    if (v === 'clip') return 'clip';
    if (v === 'scroll') return 'scroll';
    if (v === 'auto') return 'auto';
    return 'other';
  };

  const normalizePosition = (val) => {
    const v = String(val || 'static').toLowerCase();
    if (v === 'relative') return 'relative';
    if (v === 'absolute') return 'absolute';
    if (v === 'fixed') return 'fixed';
    if (v === 'sticky') return 'sticky';
    return 'static';
  };

  const walk = (el, depth, pathSegments) => {
    if (!el || el.nodeType !== 1) return;
    if (visitedNodes >= MAX_DOM_NODES) {
      domTruncated = true;
      return;
    }
    if (depth > MAX_DEPTH) {
      depthTruncated = true;
      return;
    }
    visitedNodes += 1;

    const tag = el.tagName.toLowerCase();
    const roleAttr = el.getAttribute('role');
    const role = roleAttr ? roleAttr.trim().toLowerCase().slice(0, 48) : null;
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    const bbox = {
      x: Math.round(rect.left || 0),
      y: Math.round(rect.top || 0),
      width: Math.max(0, Math.round(rect.width || 0)),
      height: Math.max(0, Math.round(rect.height || 0)),
    };
    const visible = isVisible(el, style, rect);

    if (
      visible &&
      bbox.width > 0 &&
      bbox.height > 0 &&
      bbox.y < vh &&
      bbox.x < vw &&
      bbox.y + bbox.height > 0 &&
      bbox.x + bbox.width > 0 &&
      (tag === 'header' ||
        tag === 'nav' ||
        tag === 'main' ||
        tag === 'article' ||
        tag === 'section' ||
        tag === 'footer' ||
        tag === 'h1' ||
        tag === 'p' ||
        tag === 'img' ||
        tag === 'button')
    ) {
      if (aboveFoldRects.length < ABOVE_FOLD_RECT_LIMIT) {
        aboveFoldRects.push({
          x1: Math.max(0, bbox.x),
          y1: Math.max(0, bbox.y),
          x2: Math.min(vw, bbox.x + bbox.width),
          y2: Math.min(vh, bbox.y + bbox.height),
        });
      } else {
        aboveFoldRectsTruncated = true;
      }
    }

    if (
      el.hasAttribute('aria-live') ||
      role === 'alert' ||
      role === 'status' ||
      role === 'log'
    ) {
      liveRegionCount += 1;
    }
    if (el.getAttribute('aria-invalid') === 'true') {
      ariaInvalidCount += 1;
    }

    // Track external scripts and iframes for third-party capabilities
    if (tag === 'script' && el.src) {
      const parts = sanitizeUrlParts(el.src);
      if (parts && !parts.same_origin && parts.origin) {
        const hasSri = Boolean(el.getAttribute('integrity')?.trim());
        if (!hasSri) externalScriptsWithoutSri += 1;
        const cap = thirdPartyCapabilities.get(parts.origin) || {
          script_element_present_in_main_frame: false,
          script_without_sri_count: 0,
          script_with_sri_count: 0,
          iframe_count: 0,
          unsandboxed_iframe_count: 0,
          cookies_scoped_to_origin_observed: false,
        };
        cap.script_element_present_in_main_frame = true;
        if (hasSri) cap.script_with_sri_count += 1;
        else cap.script_without_sri_count += 1;
        thirdPartyCapabilities.set(parts.origin, cap);
      }
    } else if (tag === 'iframe' && el.src) {
      const parts = sanitizeUrlParts(el.src);
      if (parts && !parts.same_origin && parts.origin) {
        const cap = thirdPartyCapabilities.get(parts.origin) || {
          script_element_present_in_main_frame: false,
          script_without_sri_count: 0,
          script_with_sri_count: 0,
          iframe_count: 0,
          unsandboxed_iframe_count: 0,
          cookies_scoped_to_origin_observed: false,
        };
        cap.iframe_count += 1;
        if (!el.hasAttribute('sandbox')) cap.unsandboxed_iframe_count += 1;
        thirdPartyCapabilities.set(parts.origin, cap);
      }
    }

    // Landmarks for VisualArtifactEvidence
    if (
      landmarks.length < 16 &&
      visible &&
      (tag === 'header' ||
        tag === 'nav' ||
        tag === 'main' ||
        tag === 'footer' ||
        tag === 'dialog' ||
        role === 'banner' ||
        role === 'navigation' ||
        role === 'main' ||
        role === 'contentinfo' ||
        role === 'dialog')
    ) {
      const vpArea = Math.max(1, vw * vh);
      const ix = Math.max(0, Math.min(vw, bbox.x + bbox.width) - Math.max(0, bbox.x));
      const iy = Math.max(0, Math.min(vh, bbox.y + bbox.height) - Math.max(0, bbox.y));
      const coverageMilli = Math.min(1000, Math.round(((ix * iy) / vpArea) * 1000));
      landmarks.push({
        landmark_role: role || tag,
        bbox,
        viewport_coverage_milli: coverageMilli,
        above_the_fold: ix > 0 && iy > 0,
      });
    }

    // Interactive inventory
    let isInteractiveCandidate = false;
    try {
      isInteractiveCandidate = el.matches(interactiveSelector);
    } catch {}
    if (isInteractiveCandidate) {
      discoveredInteractive += 1;
      if (interactiveElements.length < MAX_INTERACTIVE) {
        const typeAttr = (el.getAttribute('type') || '').trim().toLowerCase() || null;
        const accName = getAccessibleName(el);
        const nameLower = accName.toLowerCase();
        const disabled =
          Boolean(el.disabled) ||
          el.getAttribute('aria-disabled') === 'true' ||
          Boolean(el.closest('fieldset[disabled]'));
        const tabIndexAttr = el.getAttribute('tabindex');
        const tabIndex =
          tabIndexAttr !== null && !Number.isNaN(Number(tabIndexAttr))
            ? Number(tabIndexAttr)
            : el.tabIndex >= 0
              ? el.tabIndex
              : null;
        const keyboardFocusable = visible && !disabled && (el.tabIndex >= 0 || (tabIndex !== null && tabIndex >= 0));
        const expanded =
          el.hasAttribute('aria-expanded')
            ? el.getAttribute('aria-expanded') === 'true'
            : tag === 'details'
              ? Boolean(el.open)
              : tag === 'summary' && el.parentElement?.tagName === 'DETAILS'
                ? Boolean(el.parentElement.open)
                : null;
        const selected = el.hasAttribute('aria-selected')
          ? el.getAttribute('aria-selected') === 'true'
          : null;
        const checked =
          typeof el.checked === 'boolean' && (typeAttr === 'checkbox' || typeAttr === 'radio')
            ? el.checked
            : el.hasAttribute('aria-checked')
              ? el.getAttribute('aria-checked') === 'true'
              : null;
        const required = Boolean(el.required) || el.getAttribute('aria-required') === 'true';
        let invalid = el.getAttribute('aria-invalid') === 'true';
        if (!invalid && typeof el.matches === 'function') {
          try {
            invalid = el.matches(':invalid');
          } catch {}
        }
        const rawHref = el.getAttribute('href') || el.getAttribute('action') || null;
        const urlParts = rawHref ? sanitizeUrlParts(rawHref) : null;
        const targetLink = urlParts
          ? {
              href_origin: urlParts.origin,
              href_path: urlParts.path,
              same_origin: urlParts.same_origin,
              fragment_only: urlParts.fragment_only,
            }
          : null;
        const { safety, kind } = classifyInteractive(el, tag, role, typeAttr, nameLower);
        const nodeIdx = interactiveElements.length + 1;
        const identity = buildIdentity(el, pathSegments);
        interactiveElements.push({
          node: nodeIdx,
          identity,
          tag,
          role,
          control_type: typeAttr,
          name_present: accName.length > 0,
          _raw_accessible_name: accName.length > 0 ? accName : null,
          accessible_name_fingerprint: null,
          accessible_name_char_count: Array.from(accName).length,
          visible,
          enabled: !disabled,
          disabled,
          expanded,
          selected,
          checked,
          required,
          invalid,
          keyboard_focusable: keyboardFocusable,
          tab_index: tabIndex,
          bbox,
          target_link: targetLink,
          safety_class: safety,
          functional_kind: kind,
        });
        if (
          visible &&
          !disabled &&
          tag === 'summary' &&
          el.parentElement &&
          el.parentElement.tagName === 'DETAILS' &&
          !el.closest('form,a[href]') &&
          readOnlyToggleCandidates.length < 4
        ) {
          readOnlyToggleCandidates.push({
            el,
            node: nodeIdx,
            identity,
            tag,
            role,
            kind,
          });
        }
      } else {
        interactiveTruncated = true;
      }
    }

    // Visual geometry (landmarks, headings, interactive controls, or overflowing containers)
    const scrollW = Math.max(0, Math.round(el.scrollWidth || 0));
    const scrollH = Math.max(0, Math.round(el.scrollHeight || 0));
    const clientW = Math.max(0, Math.round(el.clientWidth || 0));
    const clientH = Math.max(0, Math.round(el.clientHeight || 0));
    const hOverflow = clientW > 0 && scrollW > clientW ? scrollW - clientW : 0;
    const vOverflow = clientH > 0 && scrollH > clientH ? scrollH - clientH : 0;
    const overflowX = normalizeOverflow(style?.overflowX);
    const overflowY = normalizeOverflow(style?.overflowY);
    const clippedByOverflow =
      (hOverflow > 2 && (overflowX === 'hidden' || overflowX === 'clip')) ||
      (vOverflow > 2 && (overflowY === 'hidden' || overflowY === 'clip'));
    const isGeometryTarget =
      visible &&
      (isInteractiveCandidate ||
        clippedByOverflow ||
        hOverflow > 4 ||
        tag === 'header' ||
        tag === 'nav' ||
        tag === 'main' ||
        tag === 'footer' ||
        tag === 'h1' ||
        tag === 'h2' ||
        tag === 'dialog');

    if (isGeometryTarget) {
      if (geometryElements.length < MAX_GEOMETRY) {
        let occludedAtCenter = false;
        let occludingTag = null;
        if (
          bbox.width >= 4 &&
          bbox.height >= 4 &&
          bbox.x >= 0 &&
          bbox.y >= 0 &&
          bbox.x + bbox.width <= vw &&
          bbox.y + bbox.height <= vh
        ) {
          const cx = bbox.x + Math.floor(bbox.width / 2);
          const cy = bbox.y + Math.floor(bbox.height / 2);
          const hit = document.elementFromPoint(cx, cy);
          if (hit && hit !== el && !el.contains(hit) && !hit.contains(el)) {
            occludedAtCenter = true;
            occludingTag = hit.tagName ? hit.tagName.toLowerCase() : null;
          }
        }
        const pos = normalizePosition(style?.position);
        const zRaw = style?.zIndex;
        const zIndex = zRaw && zRaw !== 'auto' && !Number.isNaN(Number(zRaw)) ? Number(zRaw) : null;
        const establishesStacking =
          (pos !== 'static' && zIndex !== null) ||
          pos === 'fixed' ||
          pos === 'sticky' ||
          Number(style?.opacity ?? 1) < 1 ||
          (style?.transform && style.transform !== 'none');

        geometryElements.push({
          node: geometryElements.length + 1,
          identity: buildIdentity(el, pathSegments),
          tag,
          role,
          bbox,
          scroll_width: scrollW,
          scroll_height: scrollH,
          client_width: clientW,
          client_height: clientH,
          overflow_x: overflowX,
          overflow_y: overflowY,
          horizontal_overflow_px: hOverflow,
          vertical_overflow_px: vOverflow,
          clipped_by_overflow: clippedByOverflow,
          occluded_at_center: occludedAtCenter,
          occluding_tag: occludingTag,
          stacking: {
            position: pos,
            z_index: zIndex,
            establishes_stacking_context: Boolean(establishesStacking),
          },
        });
      } else {
        geometryTruncated = true;
      }
    }

    // Media assets
    if (tag === 'img' || tag === 'video' || tag === 'svg') {
      if (mediaAssets.length < MAX_MEDIA) {
        const src = el.currentSrc || el.getAttribute('src') || '';
        const urlParts = sanitizeUrlParts(src);
        let formatClass = 'unknown';
        if (tag === 'svg') formatClass = 'svg';
        else if (tag === 'video') formatClass = 'video';
        else if (src.startsWith('data:')) formatClass = 'inline_data';
        else if (/\.avif(\?|$)/i.test(src)) formatClass = 'avif';
        else if (/\.webp(\?|$)/i.test(src)) formatClass = 'webp';
        else if (/\.jpe?g(\?|$)/i.test(src)) formatClass = 'jpeg';
        else if (/\.png(\?|$)/i.test(src)) formatClass = 'png';
        else if (/\.gif(\?|$)/i.test(src)) formatClass = 'gif';
        else if (/\.svg(\?|$)/i.test(src)) formatClass = 'svg';

        const natW = Math.max(0, Math.round(el.naturalWidth || el.videoWidth || bbox.width));
        const natH = Math.max(0, Math.round(el.naturalHeight || el.videoHeight || bbox.height));
        const renderedArea = Math.max(1, bbox.width * bbox.height);
        const naturalArea = natW * natH;
        const oversizeRatioMilli =
          bbox.width > 0 && bbox.height > 0 && naturalArea > 0
            ? Math.round((naturalArea / renderedArea) * 1000)
            : 1000;
        const hasWidthHeightAttrs = el.hasAttribute('width') && el.hasAttribute('height');
        const hasAspectRatio = Boolean(style?.aspectRatio && style.aspectRatio !== 'auto');
        const hasResponsiveSources =
          Boolean(el.getAttribute('srcset')?.trim()) ||
          el.parentElement?.tagName === 'PICTURE';
        const loadingRaw = (el.getAttribute('loading') || '').trim().toLowerCase();
        const loading =
          loadingRaw === 'lazy' ? 'lazy' : loadingRaw === 'eager' ? 'eager' : 'default';
        const fetchPriority = el.getAttribute('fetchpriority')?.trim().toLowerCase() || null;
        const aboveTheFold = bbox.y < vh && bbox.y + bbox.height > 0 && bbox.x < vw && bbox.x + bbox.width > 0;
        const hasAlt = el.hasAttribute('alt');
        const altVal = el.getAttribute('alt') || '';
        const isDecorative =
          (hasAlt && altVal === '') || role === 'presentation' || role === 'none';

        mediaAssets.push({
          node: mediaAssets.length,
          identity: buildIdentity(el, pathSegments),
          tag,
          resource_origin: urlParts?.origin || null,
          resource_path: urlParts?.path || null,
          format_class: formatClass,
          rendered_width: bbox.width,
          rendered_height: bbox.height,
          natural_width: natW,
          natural_height: natH,
          oversize_ratio_milli: oversizeRatioMilli,
          has_intrinsic_sizing: hasWidthHeightAttrs || hasAspectRatio,
          has_responsive_sources: hasResponsiveSources,
          loading,
          fetch_priority: fetchPriority,
          above_the_fold: aboveTheFold,
          has_alt_attribute: hasAlt,
          is_decorative: isDecorative,
        });
      } else {
        mediaTruncated = true;
      }
    }

    // Links
    if (tag === 'a' && el.hasAttribute('href')) {
      const rawHref = el.getAttribute('href') || '';
      const parts = sanitizeUrlParts(rawHref);
      const sameOrigin = parts ? parts.same_origin : true;
      if (sameOrigin) clusterSummary.internal_links += 1;
      else clusterSummary.external_links += 1;

      let placement = 'unscoped_body';
      if (el.closest('header,nav,[role="navigation"],[role="banner"]')) {
        placement = 'header_or_nav';
        clusterSummary.header_nav_links += 1;
      } else if (el.closest('main,article,[role="main"]')) {
        placement = 'main_content';
        clusterSummary.main_content_links += 1;
      } else if (el.closest('aside,[role="complementary"]')) {
        placement = 'complementary';
      } else if (el.closest('footer,[role="contentinfo"]')) {
        placement = 'footer';
        clusterSummary.footer_links += 1;
      }

      const anchorText = getAccessibleName(el);
      const words = anchorText ? anchorText.split(/\s+/).filter(Boolean).length : 0;
      if (words === 0) clusterSummary.empty_anchor_links += 1;

      const relTokens = (el.getAttribute('rel') || '')
        .toLowerCase()
        .split(/\s+/)
        .filter(Boolean);
      const relNofollow = relTokens.includes('nofollow');
      const relNoopener = relTokens.includes('noopener') || relTokens.includes('noreferrer');
      const opensNewTab = (el.getAttribute('target') || '').toLowerCase() === '_blank';
      if (opensNewTab && !sameOrigin && !relNoopener) {
        unsafeTargetBlankLinks += 1;
      }

      if (links.length < MAX_LINKS) {
        links.push({
          link_index: links.length,
          identity: buildIdentity(el, pathSegments),
          placement_region: placement,
          target_origin: parts?.origin || null,
          target_path: parts?.path || null,
          same_origin: sameOrigin,
          fragment_only: Boolean(parts?.fragment_only),
          visible,
          anchor_word_count: words,
          _raw_anchor_text: anchorText || null,
          anchor_text_fingerprint: null,
          rel_nofollow: relNofollow,
          rel_noopener: relNoopener,
          opens_new_tab: opensNewTab,
        });
      } else {
        linksTruncated = true;
      }
    }

    // Forms
    if (tag === 'form') {
      if (forms.length < MAX_FORMS) {
        const method = (el.getAttribute('method') || 'GET').trim().toUpperCase().slice(0, 16);
        const actionRaw = el.getAttribute('action') || window.location.href;
        const parts = sanitizeUrlParts(actionRaw);
        const inputs = Array.from(el.querySelectorAll('input,select,textarea'));
        const reqCount = inputs.filter(
          (inp) => inp.required || inp.getAttribute('aria-required') === 'true'
        ).length;
        const hasSensitive = inputs.some((inp) => {
          const t = (inp.getAttribute('type') || '').toLowerCase();
          const ac = (inp.getAttribute('autocomplete') || '').toLowerCase();
          return t === 'password' || ac.includes('cc-') || ac.includes('password');
        });
        forms.push({
          form_index: forms.length,
          identity: buildIdentity(el, pathSegments),
          method,
          action_origin: parts?.origin || null,
          action_path: parts?.path || null,
          secure_same_origin_action: Boolean(
            parts && parts.same_origin && String(parts.origin || '').startsWith('https:')
          ),
          field_count: inputs.length,
          required_field_count: reqCount,
          has_sensitive_input: hasSensitive,
        });
      } else {
        formsTruncated = true;
      }
    }

    const children = el.children || [];
    const tagCounts = new Map();
    for (let i = 0; i < children.length; i += 1) {
      const child = children[i];
      if (!child || child.nodeType !== 1) continue;
      const cTag = child.tagName.toLowerCase();
      const idx = (tagCounts.get(cTag) || 0) + 1;
      tagCounts.set(cTag, idx);
      walk(child, depth + 1, pathSegments.concat([`${cTag}[${idx}]`]));
    }
  };

  if (document.body) {
    walk(document.body, 1, ['body[1]']);
  }

  // Estimated coverage of the above-the-fold viewport by retained element rectangles,
  // in thousandths. Each retained rectangle is sampled on a fixed 40x25 grid; the result
  // is a geometric estimate, not pixel-derived visual coverage or painted area.
  const COVERAGE_GRID_X = 40;
  const COVERAGE_GRID_Y = 25;
  let aboveFoldCoverageMilli = null;
  if (vw > 0 && vh > 0 && aboveFoldRects.length > 0) {
    const GRID_X = COVERAGE_GRID_X;
    const GRID_Y = COVERAGE_GRID_Y;
    let coveredCells = 0;
    for (let gx = 0; gx < GRID_X; gx += 1) {
      const cx = ((gx + 0.5) * vw) / GRID_X;
      for (let gy = 0; gy < GRID_Y; gy += 1) {
        const cy = ((gy + 0.5) * vh) / GRID_Y;
        const hit = aboveFoldRects.some(
          (r) => cx >= r.x1 && cx <= r.x2 && cy >= r.y1 && cy <= r.y2
        );
        if (hit) coveredCells += 1;
      }
    }
    aboveFoldCoverageMilli = Math.min(1000, Math.round((coveredCells / (GRID_X * GRID_Y)) * 1000));
  }

  // Bounded structural digest over the real DOM tree: tag, role, id uniqueness, and
  // disclosure state. Only a hash of this walk is persisted, never the raw structure.
  // The walk is a projection: the coverage metadata records how much of the document
  // it actually described.
  const STRUCTURE_MAX_NODES = 512;
  const STRUCTURE_MAX_DEPTH = 16;
  const structureSignature = () => {
    const parts = [];
    let nodesTruncated = false;
    let depthTruncated = false;
    const walkStructure = (el, depth) => {
      if (!el) return;
      if (parts.length >= STRUCTURE_MAX_NODES) {
        nodesTruncated = true;
        return;
      }
      if (depth > STRUCTURE_MAX_DEPTH) {
        depthTruncated = true;
        return;
      }
      const tag = (el.tagName || '').toLowerCase();
      if (!tag) return;
      const roleAttr = el.getAttribute ? el.getAttribute('role') : null;
      const role = roleAttr ? roleAttr.toLowerCase() : '';
      const rawId = typeof el.id === 'string' ? el.id.trim() : '';
      const idMarker = rawId ? (idCounts.get(rawId) === 1 ? '#' : '~') : '';
      const expanded = el.getAttribute ? (el.getAttribute('aria-expanded') || '') : '';
      const open = el.open === true ? 'o' : '';
      parts.push(`${depth}${tag}${role ? '[' + role + ']' : ''}${idMarker}${expanded}${open}`);
      const children = el.children || [];
      for (let i = 0; i < children.length && parts.length < STRUCTURE_MAX_NODES; i += 1) {
        walkStructure(children[i], depth + 1);
      }
    };
    walkStructure(document.body || document.documentElement, 0);
    return {
      signature: parts.join('|'),
      visited: parts.length,
      maxNodes: STRUCTURE_MAX_NODES,
      maxDepth: STRUCTURE_MAX_DEPTH,
      nodesTruncated,
      depthTruncated,
    };
  };

  const readStateMetrics = () => {
    const activeEl = document.activeElement;
    const activeTag = activeEl && activeEl.tagName ? activeEl.tagName.toLowerCase() : null;
    const activeRole = activeEl?.getAttribute?.('role')?.toLowerCase() || null;
    const openDialogs = document.querySelectorAll('dialog[open],[role="dialog"]:not([aria-hidden="true"]),[role="alertdialog"]:not([aria-hidden="true"])').length;
    const activeTabs = document.querySelectorAll('[role="tab"][aria-selected="true"]').length;
    const expandedControls = document.querySelectorAll('[aria-expanded="true"],details[open]').length;
    const disabledControls = document.querySelectorAll(':disabled,[aria-disabled="true"]').length;
    const requiredInputs = document.querySelectorAll('input[required],select[required],textarea[required],[aria-required="true"]').length;
    let invalidInputs = document.querySelectorAll('[aria-invalid="true"]').length;
    try {
      invalidInputs = Math.max(invalidInputs, document.querySelectorAll('input:invalid,select:invalid,textarea:invalid').length);
    } catch {}
    const loadingIndicators = document.querySelectorAll('[aria-busy="true"],[role="progressbar"]').length;
    const alertRegions = document.querySelectorAll('[role="alert"]').length;
    return {
      activeTag,
      activeRole,
      openDialogs,
      activeTabs,
      expandedControls,
      disabledControls,
      requiredInputs,
      invalidInputs,
      loadingIndicators,
      alertRegions,
    };
  };

  const initialMetrics = readStateMetrics();
  const structureWalk = structureSignature();
  const applicationState = {
    document_ready_state: String(document.readyState || 'complete'),
    location_path: (window.location?.pathname || '/').slice(0, 256),
    has_location_hash: Boolean(window.location?.hash && window.location.hash.length > 1),
    history_length: Math.max(0, Number(window.history?.length || 1)),
    active_element_tag: initialMetrics.activeTag,
    active_element_role: initialMetrics.activeRole,
    active_dialog_count: initialMetrics.openDialogs,
    modal_open: initialMetrics.openDialogs > 0,
    active_tab_count: initialMetrics.activeTabs,
    expanded_control_count: initialMetrics.expandedControls,
    disabled_control_count: initialMetrics.disabledControls,
    required_input_count: initialMetrics.requiredInputs,
    invalid_input_count: initialMetrics.invalidInputs,
    loading_indicator_count: initialMetrics.loadingIndicators,
    alert_region_count: initialMetrics.alertRegions,
    scroll_x: Math.round(window.scrollX || 0),
    scroll_y: Math.round(window.scrollY || 0),
    document_scroll_height: Math.max(
      0,
      Math.round(document.documentElement?.scrollHeight || document.body?.scrollHeight || 0)
    ),
    network_idle_reached: false,
    _raw_structural_sig: structureWalk.signature,
    structural_fingerprint: null,
    structural_fingerprint_version: 1,
    structural_nodes_visited: structureWalk.visited,
    structural_max_nodes: structureWalk.maxNodes,
    structural_max_depth: structureWalk.maxDepth,
    structural_nodes_truncated: structureWalk.nodesTruncated,
    structural_depth_truncated: structureWalk.depthTruncated,
  };

  // Discover candidate user journey scenarios from interactive controls
  const scenarioSet = new Set();
  for (const item of interactiveElements) {
    if (item.functional_kind === 'search') scenarioSet.add('site_search');
    else if (item.functional_kind === 'navigation_menu') scenarioSet.add('navigation_disclosure');
    else if (item.functional_kind === 'tabs') scenarioSet.add('tabbed_interface');
    else if (item.functional_kind === 'accordion') scenarioSet.add('accordion_expansion');
    else if (item.functional_kind === 'dialog') scenarioSet.add('modal_dismissal');
    else if (item.functional_kind === 'filter' || item.functional_kind === 'sort') scenarioSet.add('filter_or_sort');
    else if (item.functional_kind === 'pagination') scenarioSet.add('pagination_traversal');
    else if (item.functional_kind === 'language_selector') scenarioSet.add('language_selection');
    else if (item.functional_kind === 'form') scenarioSet.add('form_entry');
  }

  // Execute real bounded read-only UI toggle probes (accordions/details/tabs) and restore state
  const interactionSteps = [];
  const PROBE_WINDOW_MS = 250;
  for (let i = 0; i < readOnlyToggleCandidates.length; i += 1) {
    const cand = readOnlyToggleCandidates[i];
    const before = readStateMetrics();
    const beforeStructure = structureSignature().signature;
    const beforeResources = performance.getEntriesByType('resource').length;
    const beforeErrors = Number(window.__nzwPerf?.errors || 0);
    const actionKind = 'disclosure_toggle';
    const observationStartedMs = Math.round(performance.now());
    let termination = 'window_elapsed';
    try {
      cand.el.focus();
      cand.el.click();
    } catch {
      termination = 'action_threw';
    }
    // Bounded observation window: allows promises, timers and framework
    // scheduling triggered by the action to complete before the state is read.
    if (termination !== 'action_threw') {
      await new Promise((resolve) => setTimeout(resolve, PROBE_WINDOW_MS));
    }
    const observedWindowMs = Math.max(0, Math.round(performance.now() - observationStartedMs));
    const after = readStateMetrics();
    const afterStructure = structureSignature().signature;
    const afterResources = performance.getEntriesByType('resource').length;
    const afterErrors = Number(window.__nzwPerf?.errors || 0);
    const focusChanged = after.activeTag !== before.activeTag || after.activeRole !== before.activeRole;
    const expandedChanged = after.expandedControls !== before.expandedControls;
    const dialogChanged = after.openDialogs !== before.openDialogs;
    const sigChanged = afterStructure !== beforeStructure;
    interactionSteps.push({
      step_index: interactionSteps.length,
      action: actionKind,
      target_node: cand.node,
      target_identity: cand.identity,
      active_tag: after.activeTag || cand.tag,
      active_role: after.activeRole || cand.role,
      state_changed: focusChanged || expandedChanged || dialogChanged || sigChanged,
      focus_changed: focusChanged,
      expanded_changed: expandedChanged,
      dialog_changed: dialogChanged,
      dom_fingerprint_changed: sigChanged,
      runtime_errors_observed_in_window: Math.max(0, afterErrors - beforeErrors),
      requests_observed_in_window: Math.max(0, afterResources - beforeResources),
      observation_started_ms: observationStartedMs,
      observation_window_ms: observedWindowMs,
      window_termination: termination,
      restoration_attempted: false,
      restoration_succeeded: null,
    });
    // Restore original toggle state if we changed expansion. Restoration is
    // best-effort: application-side effects are not reversed by it.
    if (expandedChanged) {
      const step = interactionSteps[interactionSteps.length - 1];
      step.restoration_attempted = true;
      try {
        cand.el.click();
        const restored = readStateMetrics();
        step.restoration_succeeded = restored.expandedControls === before.expandedControls;
        if (step.restoration_succeeded !== true) {
          step.window_termination = 'restoration_failed';
        }
      } catch {
        step.restoration_succeeded = false;
        step.window_termination = 'restoration_failed';
      }
    }
  }

  // Web Storage enumeration using storage.key(i)
  const storageKeys = [];
  let storageKeysTruncated = false;
  let storageEnumerated = true;
  const collectStorageArea = (storageObj, areaName) => {
    if (!storageObj) {
      storageEnumerated = false;
      return;
    }
    try {
      const len = Number(storageObj.length || 0);
      for (let i = 0; i < len; i += 1) {
        if (storageKeys.length >= MAX_STORAGE_KEYS) {
          storageKeysTruncated = true;
          return;
        }
        const k = storageObj.key(i);
        if (typeof k !== 'string') continue;
        const val = storageObj.getItem(k);
        storageKeys.push({
          area: areaName,
          key: k.slice(0, 128),
          value_byte_len: typeof val === 'string' ? utf8ByteLength(val) : 0,
        });
      }
    } catch {
      storageEnumerated = false;
    }
  };
  collectStorageArea(window.localStorage, 'local_storage');
  collectStorageArea(window.sessionStorage, 'session_storage');

  // Fonts
  const fontAssets = [];
  let fontsTruncated = false;
  const preloadedFonts = document.querySelectorAll('link[rel="preload"][as="font"]').length > 0;
  try {
    if (document.fonts && typeof document.fonts.forEach === 'function') {
      document.fonts.forEach((face) => {
        if (fontAssets.length >= MAX_FONTS) {
          fontsTruncated = true;
          return;
        }
        const dispRaw = String(face.display || 'auto').toLowerCase();
        const disp = ['swap', 'optional', 'fallback', 'block'].includes(dispRaw) ? dispRaw : 'auto';
        fontAssets.push({
          index: fontAssets.length,
          font_family: String(face.family || '').replace(/^["']|["']$/g, '').slice(0, 64),
          font_style: String(face.style || 'normal').slice(0, 24),
          font_weight: String(face.weight || '400').slice(0, 24),
          status: String(face.status || 'unloaded').slice(0, 24),
          font_display: disp,
          preloaded: preloadedFonts,
        });
      });
    }
  } catch {}

  // Render-blocking classification from HTML attributes plus media evaluation.
  // Counts alone cannot distinguish parser-blocking classic scripts from deferred,
  // async, or module scripts, nor stylesheets whose media query does not match.
  const blockingClassification = [];
  let blockingHeadScripts = 0;
  let blockingHeadStylesheets = 0;
  let deferredOrAsyncScriptCount = 0;
  let nonMatchingMediaStylesheetCount = 0;
  const scriptMimeTypes = new Set([
    '',
    'text/javascript',
    'application/javascript',
    'text/ecmascript',
    'application/ecmascript',
  ]);
  for (const el of Array.from(document.querySelectorAll('script[src]')).slice(0, 64)) {
    const url = el.src || '';
    if (!url) continue;
    const typeAttr = String(el.getAttribute('type') || '').trim().toLowerCase();
    if (typeAttr === 'module') {
      deferredOrAsyncScriptCount += 1;
      blockingClassification.push({
        url,
        kind: 'script',
        blocking: 'none',
        reason: 'module_deferred_by_default',
      });
      continue;
    }
    if (!scriptMimeTypes.has(typeAttr)) {
      blockingClassification.push({
        url,
        kind: 'script',
        blocking: 'none',
        reason: 'non_javascript_type',
      });
      continue;
    }
    if (el.hasAttribute('async') || el.hasAttribute('defer')) {
      deferredOrAsyncScriptCount += 1;
      blockingClassification.push({
        url,
        kind: 'script',
        blocking: 'none',
        reason: el.hasAttribute('async') ? 'async' : 'defer',
      });
      continue;
    }
    if (el.closest('head')) {
      blockingHeadScripts += 1;
      blockingClassification.push({
        url,
        kind: 'script',
        blocking: 'confirmed',
        reason: 'parser_blocking_in_head',
      });
    } else {
      blockingClassification.push({
        url,
        kind: 'script',
        blocking: 'potential',
        reason: 'parser_blocking_after_first_paint',
      });
    }
  }
  for (const el of Array.from(document.querySelectorAll('link[rel~="stylesheet"]')).slice(0, 64)) {
    const url = el.href || '';
    if (!url) continue;
    if (el.disabled) {
      blockingClassification.push({
        url,
        kind: 'stylesheet',
        blocking: 'none',
        reason: 'disabled_by_script',
      });
      continue;
    }
    const mediaAttr = String(el.getAttribute('media') || '').trim();
    let mediaMatches = true;
    let mediaUnknown = false;
    if (mediaAttr) {
      try {
        mediaMatches = window.matchMedia(mediaAttr).matches;
      } catch {
        mediaUnknown = true;
      }
    }
    if (mediaUnknown) {
      blockingClassification.push({
        url,
        kind: 'stylesheet',
        blocking: 'unknown',
        reason: 'media_query_evaluation_failed',
      });
      continue;
    }
    if (!mediaMatches) {
      nonMatchingMediaStylesheetCount += 1;
      blockingClassification.push({
        url,
        kind: 'stylesheet',
        blocking: 'none',
        reason: 'media_query_not_matching',
      });
      continue;
    }
    if (el.closest('head')) {
      blockingHeadStylesheets += 1;
      blockingClassification.push({
        url,
        kind: 'stylesheet',
        blocking: 'confirmed',
        reason: 'head_stylesheet',
      });
    } else {
      blockingClassification.push({
        url,
        kind: 'stylesheet',
        blocking: 'potential',
        reason: 'stylesheet_after_first_paint',
      });
    }
  }
  const preloadHintCount = document.querySelectorAll('head link[rel="preload"]').length;
  const preconnectHintCount = document.querySelectorAll('head link[rel="preconnect"]').length;

  // LCP candidate approximation from largest above-the-fold heading/image/main element
  let lcpCandidate = null;
  let bestArea = 0;
  const lcpSelectors = 'img,video,h1,h2,main p,[role="main"] p';
  const lcpEls = document.querySelectorAll(lcpSelectors);
  for (let i = 0; i < Math.min(lcpEls.length, 64); i += 1) {
    const el = lcpEls[i];
    const r = el.getBoundingClientRect();
    const st = window.getComputedStyle(el);
    if (!isVisible(el, st, r)) continue;
    const b = {
      x: Math.round(r.left || 0),
      y: Math.round(r.top || 0),
      width: Math.max(0, Math.round(r.width || 0)),
      height: Math.max(0, Math.round(r.height || 0)),
    };
    if (b.y >= vh || b.x >= vw) continue;
    const area = b.width * b.height;
    if (area > bestArea) {
      bestArea = area;
      const src = el.currentSrc || el.getAttribute('src') || null;
      const parts = src ? sanitizeUrlParts(src) : null;
      lcpCandidate = {
        identity: buildIdentity(el, [el.tagName.toLowerCase()]),
        tag: el.tagName.toLowerCase(),
        render_time_ms: null,
        size_px_sq: area,
        bbox: b,
        resource_origin: parts?.origin || null,
        resource_path: parts?.path || null,
        above_the_fold: true,
      };
    }
  }

  // Indexability & canonicals
  const metaRobots = Array.from(
    document.querySelectorAll('meta[name="robots" i],meta[name="googlebot" i]')
  )
    .map((m) => (m.getAttribute('content') || '').toLowerCase())
    .join(',');
  const renderedMetaNoindex = metaRobots.includes('noindex');
  const renderedMetaNofollow = metaRobots.includes('nofollow');
  const canonicalLinks = Array.from(document.querySelectorAll('link[rel="canonical" i]'));
  const canonicalHrefs = canonicalLinks
    .map((l) => (l.getAttribute('href') || '').trim())
    .filter(Boolean);
  const firstCanonicalParts = canonicalHrefs.length > 0 ? sanitizeUrlParts(canonicalHrefs[0]) : null;
  const currentParts = sanitizeUrlParts(window.location.href);
  const canonicalIsSelf = Boolean(
    firstCanonicalParts &&
      currentParts &&
      firstCanonicalParts.origin === currentParts.origin &&
      firstCanonicalParts.path === currentParts.path
  );
  const hasPaginationRel =
    document.querySelectorAll('link[rel="next" i],link[rel="prev" i]').length > 0;
  const hreflangEls = Array.from(
    document.querySelectorAll('link[rel="alternate" i][hreflang]')
  );
  const hreflangAlternates = [];
  const seenHreflangCodes = new Set();
  let duplicateHreflang = false;
  for (let i = 0; i < Math.min(hreflangEls.length, MAX_HREFLANG); i += 1) {
    const el = hreflangEls[i];
    const code = (el.getAttribute('hreflang') || '').trim().toLowerCase().slice(0, 32);
    if (!code) continue;
    if (seenHreflangCodes.has(code)) duplicateHreflang = true;
    seenHreflangCodes.add(code);
    const parts = sanitizeUrlParts(el.getAttribute('href') || '');
    const isSelf = Boolean(
      parts &&
        currentParts &&
        parts.origin === currentParts.origin &&
        parts.path === currentParts.path
    );
    hreflangAlternates.push({
      hreflang: code,
      href_origin: parts?.origin || null,
      href_path: parts?.path || null,
      is_self_referential: isSelf,
    });
  }

  // Structured data & social preview card
  const jsonLdScripts = Array.from(
    document.querySelectorAll('script[type="application/ld+json" i]')
  );
  let malformedJsonLdCount = 0;
  const entities = [];
  let entitiesTruncated = false;
  const structuredIssues = [];

  const requiredBySchemaType = {
    Product: ['name'],
    Article: ['headline'],
    NewsArticle: ['headline'],
    BlogPosting: ['headline'],
    Organization: ['name'],
    BreadcrumbList: ['itemListElement'],
    FAQPage: ['mainEntity'],
  };

  const pushEntity = (syntax, obj) => {
    if (!obj || typeof obj !== 'object') return;
    if (Array.isArray(obj['@graph'])) {
      for (const item of obj['@graph']) pushEntity(syntax, item);
      return;
    }
    if (entities.length >= MAX_ENTITIES) {
      entitiesTruncated = true;
      return;
    }
    const rawType = Array.isArray(obj['@type']) ? obj['@type'][0] : obj['@type'];
    const schemaType = String(rawType || 'Thing').trim().slice(0, 64);
    const ctx = String(obj['@context'] || '').toLowerCase();
    const isSchemaOrg = ctx.includes('schema.org') || syntax !== 'json_ld';
    const propKeys = Object.keys(obj)
      .filter((k) => !k.startsWith('@'))
      .sort()
      .slice(0, 32);
    const reqList = requiredBySchemaType[schemaType] || [];
    const missingReq = reqList.filter((r) => !(r in obj) || obj[r] === null || obj[r] === '');
    if (missingReq.length > 0) {
      structuredIssues.push(`missing_required:${schemaType}:${missingReq.join(',')}`);
    }
    entities.push({
      entity_index: entities.length,
      syntax,
      schema_type: schemaType,
      is_schema_org: isSchemaOrg,
      property_keys: propKeys,
      missing_required_fields: missingReq,
      valid: missingReq.length === 0,
    });
  };

  for (const scr of jsonLdScripts) {
    const raw = (scr.textContent || '').trim();
    if (!raw) continue;
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        for (const item of parsed) pushEntity('json_ld', item);
      } else {
        pushEntity('json_ld', parsed);
      }
    } catch {
      malformedJsonLdCount += 1;
      structuredIssues.push('malformed_json_ld');
    }
  }

  const microdataEls = Array.from(document.querySelectorAll('[itemscope][itemtype]'));
  for (let i = 0; i < Math.min(microdataEls.length, 16); i += 1) {
    if (entities.length >= MAX_ENTITIES) {
      entitiesTruncated = true;
      break;
    }
    const el = microdataEls[i];
    const itemType = (el.getAttribute('itemtype') || '').trim();
    const schemaType = itemType.split('/').pop() || 'Thing';
    const props = Array.from(el.querySelectorAll('[itemprop]'))
      .map((p) => (p.getAttribute('itemprop') || '').trim())
      .filter(Boolean);
    const uniqueProps = Array.from(new Set(props)).sort().slice(0, 32);
    entities.push({
      entity_index: entities.length,
      syntax: 'microdata',
      schema_type: schemaType.slice(0, 64),
      is_schema_org: itemType.toLowerCase().includes('schema.org'),
      property_keys: uniqueProps,
      missing_required_fields: [],
      valid: true,
    });
  }

  const hasMeta = (selector) => {
    const el = document.querySelector(selector);
    const content = el ? (el.getAttribute('content') || '').trim() : '';
    return content.length > 0;
  };
  const ogTitle = hasMeta('meta[property="og:title" i]');
  const ogDesc = hasMeta('meta[property="og:description" i]');
  const ogImg = hasMeta('meta[property="og:image" i]');
  const ogUrl = hasMeta('meta[property="og:url" i]');
  const ogType = hasMeta('meta[property="og:type" i]');
  const twitterCardEl = document.querySelector('meta[name="twitter:card" i],meta[property="twitter:card" i]');
  const twitterCardKind = twitterCardEl
    ? (twitterCardEl.getAttribute('content') || '').trim().slice(0, 48) || null
    : null;
  const twitterTitle = hasMeta('meta[name="twitter:title" i],meta[property="twitter:title" i]') || ogTitle;
  const twitterImg = hasMeta('meta[name="twitter:image" i],meta[property="twitter:image" i]') || ogImg;
  const rawTitle = (document.title || '').replace(/\s+/g, ' ').trim();

  // Security challenge indicators
  const challengeIndicators = [];
  if (document.querySelector('#cf-wrapper,#challenge-running,script[src*="cdn-cgi/challenge-platform"]')) {
    challengeIndicators.push('cloudflare_challenge');
  }
  if (document.querySelector('.g-recaptcha,.h-captcha,iframe[src*="recaptcha"],iframe[src*="hcaptcha"],iframe[src*="challenges.cloudflare.com"]')) {
    challengeIndicators.push('captcha_widget');
  }
  const captchaFrames = document.querySelectorAll(
    'iframe[src*="recaptcha"],iframe[src*="hcaptcha"],iframe[src*="challenges.cloudflare.com"],iframe[src*="datadome"]'
  ).length;
  const metaCspPresent = Boolean(
    document.querySelector('meta[http-equiv="Content-Security-Policy" i]')
  );
  const manifestLinkPresent = Boolean(document.querySelector('link[rel="manifest" i]'));

  return {
    viewport_width: vw,
    viewport_height: vh,
    interactive_inventory: {
      elements: interactiveElements,
      limits: {
        max_elements: MAX_INTERACTIVE,
        discovered_elements: discoveredInteractive,
        elements_truncated: interactiveTruncated,
      },
    },
    application_state: applicationState,
    user_journey_trace: {
      candidate_scenarios: Array.from(scenarioSet),
      steps: interactionSteps,
      truncated: readOnlyToggleCandidates.length > 16,
      probe_policy: interactionSteps.length > 0 ? 'restricted_behavioural_probe' : 'passive_only',
      network_requests_suppressed: false,
    },
    visual_geometry: {
      viewport_width: vw,
      viewport_height: vh,
      elements: geometryElements,
      limits: {
        dom_truncated: domTruncated,
        depth_truncated: depthTruncated,
        elements_truncated: geometryTruncated,
      },
    },
    storage_partial: {
      storage_keys: storageKeys,
      storage_keys_truncated: storageKeysTruncated,
      storage_enumerated: storageEnumerated,
    },
    third_party_capabilities: Array.from(thirdPartyCapabilities.entries()),
    security_dom: {
      meta_csp_present: metaCspPresent,
      external_scripts_without_sri: externalScriptsWithoutSri,
      unsafe_target_blank_links: unsafeTargetBlankLinks,
      challenge_indicators: challengeIndicators,
      captcha_frame_count: captchaFrames,
    },
    performance_dom: {
      lcp_candidate: lcpCandidate,
      blocking_head_scripts: blockingHeadScripts,
      blocking_head_stylesheets: blockingHeadStylesheets,
      blocking_classification: blockingClassification,
      deferred_or_async_script_count: deferredOrAsyncScriptCount,
      non_matching_media_stylesheet_count: nonMatchingMediaStylesheetCount,
      preload_hint_count: preloadHintCount,
      preconnect_hint_count: preconnectHintCount,
    },
    media_and_fonts: {
      media_assets: mediaAssets,
      media_truncated: mediaTruncated,
      font_assets: fontAssets,
      fonts_truncated: fontsTruncated,
      total_font_transfer_bytes: 0,
    },
    indexability_dom: {
      rendered_meta_noindex: renderedMetaNoindex,
      rendered_meta_nofollow: renderedMetaNofollow,
      canonical_tag_count: canonicalLinks.length,
      distinct_canonical_count: new Set(canonicalHrefs).size,
      rendered_canonical_origin: firstCanonicalParts?.origin || null,
      rendered_canonical_path: firstCanonicalParts?.path || null,
      canonical_is_self_referential: canonicalIsSelf,
      has_pagination_rel_links: hasPaginationRel,
      hreflang_alternates: hreflangAlternates,
      hreflang_truncated: hreflangEls.length > MAX_HREFLANG,
      duplicate_hreflang: duplicateHreflang,
    },
    structured_data: {
      json_ld_block_count: jsonLdScripts.length,
      malformed_json_ld_count: malformedJsonLdCount,
      entities,
      entities_truncated: entitiesTruncated,
      social_card: {
        og_title_present: ogTitle,
        og_description_present: ogDesc,
        og_image_present: ogImg,
        og_url_present: ogUrl,
        og_type_present: ogType,
        og_complete: ogTitle && ogDesc && ogImg && ogUrl,
        twitter_card_kind: twitterCardKind,
        twitter_title_present: twitterTitle,
        twitter_image_present: twitterImg,
        twitter_complete: Boolean(twitterCardKind) && twitterTitle && twitterImg,
        _raw_title: rawTitle || null,
        rendered_title_fingerprint: null,
      },
      issues: structuredIssues,
    },
    link_graph: {
      cluster_summary: clusterSummary,
      links,
      links_truncated: linksTruncated,
      forms,
      forms_truncated: formsTruncated,
    },
    visual_dom: {
      above_fold_retained_element_coverage_milli: aboveFoldCoverageMilli,
      coverage_grid_columns: aboveFoldCoverageMilli === null ? null : COVERAGE_GRID_X,
      coverage_grid_rows: aboveFoldCoverageMilli === null ? null : COVERAGE_GRID_Y,
      coverage_retained_element_count: aboveFoldRects.length,
      coverage_retained_element_limit: ABOVE_FOLD_RECT_LIMIT,
      coverage_elements_truncated: aboveFoldRectsTruncated,
      landmarks,
    },
    manifest_link_present: manifestLinkPresent,
    beh_extra: {
      live_region_count: liveRegionCount,
      aria_invalid_count: ariaInvalidCount,
    },
  };
}

function assembleSensoryInventories(params, sha256HexFn) {
  const {
    bundle,
    finalUrl,
    mainResponseHeaders,
    mainStatusCode,
    resources,
    cookies,
    viewports,
    perfObs,
    screenshotSha256,
    screenshotByteLen,
    swInfo,
    indexedDbInfo,
    cookiesEnumerated,
    loadTimedOut,
    pendingRequestsCount,
  } = params;

  const hashIdentity = (idObj) => {
    if (!idObj || !idObj.id) return;
    if (idObj.id._raw_id) {
      idObj.id.key = `sha256:${sha256HexFn(idObj.id._raw_id)}`;
      delete idObj.id._raw_id;
    }
  };

  if (!bundle || typeof bundle !== 'object') {
    return {};
  }

  // Finalize hashes on interactive_inventory
  for (const el of bundle.interactive_inventory?.elements || []) {
    hashIdentity(el.identity);
    if (el._raw_accessible_name) {
      el.accessible_name_fingerprint = {
        version: 1,
        digest: sha256HexFn(el._raw_accessible_name),
      };
    }
    delete el._raw_accessible_name;
  }

  // Finalize application_state
  const appState = bundle.application_state || {};
  appState.network_idle_reached = !loadTimedOut && Number(pendingRequestsCount || 0) === 0;
  if (appState._raw_structural_sig) {
    appState.structural_fingerprint = sha256HexFn(appState._raw_structural_sig);
  }
  delete appState._raw_structural_sig;

  // Finalize user_journey_trace
  for (const step of bundle.user_journey_trace?.steps || []) {
    if (step.target_identity) hashIdentity(step.target_identity);
  }

  // Finalize visual_geometry
  for (const geo of bundle.visual_geometry?.elements || []) {
    hashIdentity(geo.identity);
  }

  // Finalize cookie_and_storage
  let pageHost = '';
  let pageOrigin = '';
  try {
    const u = new URL(finalUrl);
    pageHost = u.hostname.toLowerCase();
    pageOrigin = u.origin;
  } catch {}

  const rawCookies = Array.isArray(cookies) ? cookies : [];
  const mappedCookies = rawCookies.slice(0, 128).map((c) => {
    const name = String(c.name || '').slice(0, 128);
    const domain = String(c.domain || '').toLowerCase().replace(/^\./, '');
    const sameSiteRaw = String(c.sameSite || '').toLowerCase();
    const sameSite =
      sameSiteRaw === 'strict'
        ? 'strict'
        : sameSiteRaw === 'lax'
          ? 'lax'
          : sameSiteRaw === 'none'
            ? 'none'
            : 'unspecified';
    const thirdParty = pageHost && domain ? !hostMatchesCookieDomain(pageHost, domain) : null;
    return {
      name,
      domain: String(c.domain || '').slice(0, 128),
      path: String(c.path || '/').slice(0, 128),
      secure: Boolean(c.secure),
      http_only: Boolean(c.httpOnly),
      same_site: sameSite,
      session: Boolean(c.session),
      value_byte_len: utf8ByteLength(c.value),
      third_party: thirdParty,
      has_security_prefix: name.startsWith('__Host-') || name.startsWith('__Secure-'),
      observed_before_consent: null,
    };
  });

  const idbList = Array.isArray(indexedDbInfo?.databases) ? indexedDbInfo.databases : [];
  const cookieAndStorage = {
    cookies: mappedCookies,
    storage_keys: bundle.storage_partial?.storage_keys || [],
    indexed_db_count: idbList.length,
    indexed_db_databases: idbList,
    indexed_db_enumerated: Boolean(indexedDbInfo?.enumerated),
    cookies_enumerated: Boolean(cookiesEnumerated),
    storage_enumerated: Boolean(bundle.storage_partial?.storage_enumerated),
    limits: {
      max_cookies: 128,
      cookies_truncated: rawCookies.length > 128,
      max_storage_keys: 128,
      storage_keys_truncated: Boolean(bundle.storage_partial?.storage_keys_truncated),
    },
  };

  // Finalize third_party_inventory
  const capMap = new Map(bundle.third_party_capabilities || []);
  const tpOrigins = new Map();
  let fontTransferBytes = 0;
  let swServedCount = 0;
  let diskCacheCount = 0;
  let mixedContentCount = 0;
  const isHttpsPage = String(finalUrl || '').startsWith('https://');

  const cookieDomains = mappedCookies
    .map((c) => String(c.domain || '').toLowerCase().replace(/^\./, ''))
    .filter(Boolean);
  for (const res of Array.isArray(resources) ? resources : []) {
    const rType = String(res.resource_type || '');
    const tBytes = Number(res.transfer_size || 0);
    if (rType === 'Font') fontTransferBytes += tBytes;
    if (res.cache_source === 'service_worker') swServedCount += 1;
    else if (res.cache_source === 'disk_cache' || res.cache_source === 'prefetch_cache') {
      diskCacheCount += 1;
    }
    if (isHttpsPage && String(res.url || '').startsWith('http://')) {
      mixedContentCount += 1;
    }
    let resOrigin = '';
    try {
      resOrigin = new URL(res.url).origin;
    } catch {}
    if (!resOrigin || resOrigin === pageOrigin) continue;
    const entry = tpOrigins.get(resOrigin) || {
      origin: resOrigin,
      total_requests: 0,
      total_transfer_bytes: 0,
      script_requests: 0,
      xhr_fetch_beacon_requests: 0,
      iframe_requests: 0,
      http_error_response_count: 0,
      capability: capMap.get(resOrigin) || {
        script_element_present_in_main_frame: false,
        script_without_sri_count: 0,
        script_with_sri_count: 0,
        iframe_count: 0,
        unsandboxed_iframe_count: 0,
        cookies_scoped_to_origin_observed: false,
      },
    };
    entry.total_requests += 1;
    entry.total_transfer_bytes += tBytes;
    if (rType === 'Script') entry.script_requests += 1;
    else if (rType === 'XHR' || rType === 'Fetch' || rType === 'Ping') {
      entry.xhr_fetch_beacon_requests += 1;
    } else if (rType === 'Document') {
      entry.iframe_requests += 1;
    }
    if (res.status_code && res.status_code >= 400) {
      entry.http_error_response_count += 1;
    }
    let originHost = '';
    try {
      originHost = new URL(resOrigin).hostname.toLowerCase();
    } catch {}
    if (originHost && cookieDomains.some((d) => hostMatchesCookieDomain(originHost, d))) {
      entry.capability.cookies_scoped_to_origin_observed = true;
    }
    tpOrigins.set(resOrigin, entry);
  }
  const tpList = Array.from(tpOrigins.values()).sort(
    (a, b) => b.total_requests - a.total_requests
  );
  const thirdPartyInventory = {
    origins: tpList.slice(0, 128),
    truncated: tpList.length > 128,
  };

  // Security posture & challenge
  const hdrs = mainResponseHeaders || {};
  const getHdr = (name) => {
    const key = Object.keys(hdrs).find((k) => k.toLowerCase() === name.toLowerCase());
    return key ? String(hdrs[key] || '') : '';
  };
  const cspHeader = getHdr('content-security-policy');
  const cspRoHeader = getHdr('content-security-policy-report-only');
  const hstsHeader = getHdr('strict-transport-security');
  let hstsMaxAge = null;
  const hstsMatch = hstsHeader.match(/max-age=(\d+)/i);
  if (hstsMatch) hstsMaxAge = Number(hstsMatch[1]);
  const xcto = getHdr('x-content-type-options').toLowerCase().includes('nosniff');
  const xfo =
    Boolean(getHdr('x-frame-options')) || cspHeader.toLowerCase().includes('frame-ancestors');

  const securityPosture = {
    https_final_url: isHttpsPage,
    csp_present: Boolean(cspHeader) || Boolean(bundle.security_dom?.meta_csp_present),
    csp_report_only: !cspHeader && Boolean(cspRoHeader),
    csp_unsafe_inline_script: cspHeader.includes("'unsafe-inline'"),
    csp_unsafe_eval_script: cspHeader.includes("'unsafe-eval'"),
    hsts_present: Boolean(hstsHeader),
    hsts_max_age_secs: hstsMaxAge,
    x_content_type_options_nosniff: xcto,
    x_frame_options_present: xfo,
    referrer_policy_present: Boolean(getHdr('referrer-policy')),
    permissions_policy_present: Boolean(getHdr('permissions-policy')),
    coop_present: Boolean(getHdr('cross-origin-opener-policy')),
    coep_present: Boolean(getHdr('cross-origin-embedder-policy')),
    corp_present: Boolean(getHdr('cross-origin-resource-policy')),
    runtime_csp_violation_count: 0,
    mixed_content_request_count: mixedContentCount,
    external_scripts_without_sri: Number(bundle.security_dom?.external_scripts_without_sri || 0),
    unsafe_target_blank_links: Number(bundle.security_dom?.unsafe_target_blank_links || 0),
  };

  const indicators = Array.isArray(bundle.security_dom?.challenge_indicators)
    ? bundle.security_dom.challenge_indicators.slice()
    : [];
  if (getHdr('cf-mitigated')) indicators.push('cf-mitigated');
  let provider = null;
  if (indicators.some((i) => i.includes('cloudflare') || i === 'cf-mitigated')) {
    provider = 'cloudflare';
  } else if (indicators.includes('captcha_widget')) {
    provider = 'captcha_widget';
  } else if (mainStatusCode === 403 || mainStatusCode === 429 || mainStatusCode === 503) {
    if (indicators.length > 0) provider = 'generic_interstitial';
  }
  const securityChallenge = {
    challenge_detected: indicators.length > 0,
    provider,
    blocking_page_content:
      indicators.length > 0 &&
      (mainStatusCode === 403 || mainStatusCode === 429 || mainStatusCode === 503),
    http_status_code: mainStatusCode || null,
    captcha_frame_count: Number(bundle.security_dom?.captcha_frame_count || 0),
    matched_indicators: indicators,
  };

  // Performance attribution
  const lcp = bundle.performance_dom?.lcp_candidate || null;
  if (lcp) {
    if (lcp.identity) hashIdentity(lcp.identity);
    // A geometry-derived candidate must never inherit measured LCP timing.
    lcp.candidate_source = 'dom_geometry_heuristic';
    lcp.render_time_ms = null;
  }
  const shiftRegions = Array.isArray(perfObs?.shift_regions)
    ? perfObs.shift_regions.slice(0, 16).map((s, idx) => ({
        shift_index: idx,
        score_milli: Math.max(0, Math.round(Number(s.value || 0) * 1000)),
        start_time_ms: Math.max(0, Math.round(Number(s.start_time || 0))),
        window_index:
          typeof s.window_index === 'number' && Number.isInteger(s.window_index) && s.window_index >= 0
            ? s.window_index
            : null,
        primary_node_identity: null,
        primary_node_tag: s.tag ? String(s.tag).slice(0, 32) : null,
      }))
    : [];
  const totalClsMilli =
    typeof perfObs?.cls_thousandths === 'number'
      ? Math.max(0, Math.round(perfObs.cls_thousandths))
      : null;
  const blockingClassification = Array.isArray(bundle.performance_dom?.blocking_classification)
    ? bundle.performance_dom.blocking_classification
    : null;
  const resourcesByUrl = new Map();
  for (const r of Array.isArray(resources) ? resources : []) {
    if (r && typeof r.url === 'string') resourcesByUrl.set(r.url, r);
  }
  const bytesForClass = (blockingClass) => {
    if (!blockingClassification) return null;
    const members = blockingClassification.filter((c) => c && c.blocking === blockingClass);
    if (members.length === 0) return 0;
    let total = 0;
    for (const m of members) {
      const r = resourcesByUrl.get(m.url);
      if (!r || typeof r.transfer_size !== 'number' || !Number.isFinite(r.transfer_size)) {
        // One unobserved member is enough to make the total unrepresentable.
        return null;
      }
      total += Math.max(0, r.transfer_size);
    }
    return total;
  };
  const unknownBlockingResourceCount = blockingClassification
    ? blockingClassification.filter((c) => c && c.blocking === 'unknown').length
    : 0;
  const performanceAttribution = {
    lcp_candidate: lcp,
    total_cls_milli: totalClsMilli,
    cls_shift_regions: shiftRegions,
    render_blocking_chain: {
      blocking_head_scripts: Number(bundle.performance_dom?.blocking_head_scripts || 0),
      blocking_head_stylesheets: Number(bundle.performance_dom?.blocking_head_stylesheets || 0),
      deferred_or_async_script_count: Number(
        bundle.performance_dom?.deferred_or_async_script_count || 0
      ),
      non_matching_media_stylesheet_count: Number(
        bundle.performance_dom?.non_matching_media_stylesheet_count || 0
      ),
      preload_hint_count: Number(bundle.performance_dom?.preload_hint_count || 0),
      preconnect_hint_count: Number(bundle.performance_dom?.preconnect_hint_count || 0),
      confirmed_blocking_transfer_bytes: bytesForClass('confirmed'),
      potential_blocking_transfer_bytes: bytesForClass('potential'),
      unknown_blocking_resource_count: unknownBlockingResourceCount,
    },
  };

  // Media and fonts
  const mediaAndFonts = bundle.media_and_fonts || {
    media_assets: [],
    media_truncated: false,
    font_assets: [],
    fonts_truncated: false,
    total_font_transfer_bytes: 0,
  };
  for (const m of mediaAndFonts.media_assets || []) {
    hashIdentity(m.identity);
  }
  mediaAndFonts.total_font_transfer_bytes = fontTransferBytes;

  // Indexability authority
  const xRobots = getHdr('x-robots-tag').toLowerCase();
  const httpNoindex = xRobots.includes('noindex');
  const httpNofollow = xRobots.includes('nofollow');
  const idxDom = bundle.indexability_dom || {};
  const conflicts = [];
  if (Number(idxDom.distinct_canonical_count || 0) > 1) {
    conflicts.push('multiple_conflicting_canonicals');
  }
  if ((httpNoindex || idxDom.rendered_meta_noindex) && idxDom.canonical_tag_count > 0 && !idxDom.canonical_is_self_referential) {
    conflicts.push('noindex_with_non_self_canonical');
  }
  if (idxDom.duplicate_hreflang) {
    conflicts.push('duplicate_hreflang_code');
  }
  if (
    Array.isArray(idxDom.hreflang_alternates) &&
    idxDom.hreflang_alternates.length > 0 &&
    !idxDom.hreflang_alternates.some((h) => h.is_self_referential)
  ) {
    conflicts.push('missing_self_referential_hreflang');
  }

  const indexabilityAuthority = {
    effectively_indexable:
      mainStatusCode === 200 && !httpNoindex && !idxDom.rendered_meta_noindex,
    http_x_robots_noindex: httpNoindex,
    http_x_robots_nofollow: httpNofollow,
    rendered_meta_noindex: Boolean(idxDom.rendered_meta_noindex),
    rendered_meta_nofollow: Boolean(idxDom.rendered_meta_nofollow),
    canonical_tag_count: Number(idxDom.canonical_tag_count || 0),
    rendered_canonical_origin: idxDom.rendered_canonical_origin || null,
    rendered_canonical_path: idxDom.rendered_canonical_path || null,
    canonical_is_self_referential: Boolean(idxDom.canonical_is_self_referential),
    has_pagination_rel_links: Boolean(idxDom.has_pagination_rel_links),
    hreflang_alternates: idxDom.hreflang_alternates || [],
    hreflang_truncated: Boolean(idxDom.hreflang_truncated),
    conflicts,
  };

  // Structured data
  const structuredData = bundle.structured_data || {};
  if (structuredData.social_card) {
    if (structuredData.social_card._raw_title) {
      structuredData.social_card.rendered_title_fingerprint = {
        version: 1,
        digest: sha256HexFn(structuredData.social_card._raw_title),
      };
    }
    delete structuredData.social_card._raw_title;
  }

  // Responsive comparison requires two real viewport observations. A missing
  // viewport must never be replaced by an assumed width, and an unknown metric
  // must never be coerced to zero.
  const observedNumber = (value) =>
    typeof value === 'number' && Number.isFinite(value) ? value : null;
  const observedViewport = (name) => {
    const vp = (Array.isArray(viewports) ? viewports : []).find((v) => v.name === name);
    if (!vp || typeof vp !== 'object') return null;
    const width = observedNumber(vp.width);
    const scrollWidth = observedNumber(vp.scroll_width);
    if (width === null || scrollWidth === null) return null;
    return {
      width,
      scrollWidth,
      visibleControls: observedNumber(vp.visible_controls),
      overflowPx: observedNumber(vp.horizontal_overflow_px),
      smallTargets: observedNumber(vp.small_touch_targets_count),
    };
  };
  const desktopVp = observedViewport('desktop');
  const mobileVp = observedViewport('mobile');
  let responsiveComparison = null;
  if (desktopVp && mobileVp) {
    const anomalies = [];
    if (mobileVp.overflowPx !== null && mobileVp.overflowPx > 0) {
      anomalies.push({
        anomaly_index: anomalies.length,
        kind: 'mobile_horizontal_overflow',
        identity: null,
        tag: 'body',
        mobile_metric_px: mobileVp.scrollWidth,
        desktop_metric_px: desktopVp.scrollWidth,
      });
    }
    if (mobileVp.smallTargets !== null && mobileVp.smallTargets > 0) {
      anomalies.push({
        anomaly_index: anomalies.length,
        kind: 'undersized_mobile_touch_target',
        identity: null,
        tag: 'button',
        mobile_metric_px: mobileVp.smallTargets,
        desktop_metric_px: desktopVp.smallTargets,
      });
    }
    responsiveComparison = {
      mobile_viewport_width: mobileVp.width,
      mobile_scroll_width: mobileVp.scrollWidth,
      desktop_viewport_width: desktopVp.width,
      desktop_scroll_width: desktopVp.scrollWidth,
      desktop_visible_controls: desktopVp.visibleControls,
      mobile_visible_controls: mobileVp.visibleControls,
      mobile_undersized_touch_targets: mobileVp.smallTargets,
      anomalies,
      anomalies_truncated: false,
    };
  }

  // Link graph
  const linkGraph = bundle.link_graph || {
    cluster_summary: {
      internal_links: 0,
      external_links: 0,
      header_nav_links: 0,
      main_content_links: 0,
      footer_links: 0,
      empty_anchor_links: 0,
    },
    links: [],
    links_truncated: false,
    forms: [],
    forms_truncated: false,
  };
  for (const l of linkGraph.links || []) {
    hashIdentity(l.identity);
    if (l._raw_anchor_text) {
      l.anchor_text_fingerprint = {
        version: 1,
        digest: sha256HexFn(l._raw_anchor_text),
      };
    }
    delete l._raw_anchor_text;
  }
  for (const f of linkGraph.forms || []) {
    hashIdentity(f.identity);
  }

  // Visual artifacts
  const visualDom = bundle.visual_dom || {};
  const observedVisualNumber = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
  const visualArtifacts = {
    viewport_screenshot_sha256: screenshotSha256 || null,
    screenshot_byte_len: observedVisualNumber(screenshotByteLen),
    viewport_width: observedVisualNumber(bundle.viewport_width),
    viewport_height: observedVisualNumber(bundle.viewport_height),
    above_fold_retained_element_coverage_milli: observedVisualNumber(
      visualDom.above_fold_retained_element_coverage_milli
    ),
    coverage_grid_columns: observedVisualNumber(visualDom.coverage_grid_columns),
    coverage_grid_rows: observedVisualNumber(visualDom.coverage_grid_rows),
    coverage_retained_element_count: observedVisualNumber(visualDom.coverage_retained_element_count),
    coverage_retained_element_limit: observedVisualNumber(visualDom.coverage_retained_element_limit),
    coverage_elements_truncated: Boolean(visualDom.coverage_elements_truncated),
    landmarks: visualDom.landmarks || [],
  };

  // Service worker lifecycle
  const regs = Array.isArray(swInfo?.registrations) ? swInfo.registrations : [];
  const firstReg = regs[0] || null;
  let regState = 'none';
  if (firstReg) {
    const st = String(firstReg.state || '').toLowerCase();
    if (st === 'activated') regState = 'activated';
    else if (st === 'activating') regState = 'activating';
    else if (st === 'waiting' || st === 'installed') regState = 'waiting';
    else if (st === 'installing') regState = 'installing';
  }
  const cacheBuckets = Array.isArray(swInfo?.cache_names) ? swInfo.cache_names.slice(0, 16) : [];
  const serviceWorker = {
    registration_state: regState,
    page_controlled: Boolean(swInfo?.controller_present),
    script_path: firstReg?.script_path || null,
    scope_path: firstReg?.scope_path || null,
    cache_storage_bucket_count: cacheBuckets.length,
    cache_bucket_names: cacheBuckets,
    sw_served_request_count: swServedCount,
    disk_or_prefetch_cache_request_count: diskCacheCount,
    manifest_link_present: Boolean(bundle.manifest_link_present),
  };

  return {
    interactive_inventory: bundle.interactive_inventory,
    application_state: appState,
    user_journey_trace: bundle.user_journey_trace,
    visual_geometry: bundle.visual_geometry,
    cookie_and_storage: cookieAndStorage,
    third_party_inventory: thirdPartyInventory,
    security_posture: securityPosture,
    security_challenge: securityChallenge,
    performance_attribution: performanceAttribution,
    media_and_fonts: mediaAndFonts,
    indexability_authority: indexabilityAuthority,
    structured_data: structuredData,
    responsive_comparison: responsiveComparison,
    link_graph: linkGraph,
    visual_artifacts: visualArtifacts,
    service_worker: serviceWorker,
    beh_extra: bundle.beh_extra,
  };
}
