function sha256HexUtf8(value) {
  const { createHash } = require('node:crypto');
  return createHash('sha256').update(String(value || '').normalize('NFC'), 'utf8').digest('hex');
}

function sha256HexUtf16Le(value) {
  const { createHash } = require('node:crypto');
  return createHash('sha256').update(String(value || ''), 'utf16le').digest('hex');
}

function collectInPageSensoryBundle() {
  const MAX_INTERACTIVE = 128;
  const MAX_GEOMETRY = 128;
  const MAX_LINKS = 128;
  const MAX_FORMS = 32;
  const MAX_IMAGES = 64;
  const MAX_FONTS = 32;
  const MAX_STRUCTURED = 32;
  const MAX_STORAGE_KEYS = 64;

  const vw = Math.max(0, Math.round(window.innerWidth || document.documentElement?.clientWidth || 0));
  const vh = Math.max(0, Math.round(window.innerHeight || document.documentElement?.clientHeight || 0));

  const cleanToken = (raw, maxLen = 64) => {
    if (typeof raw !== 'string') return '';
    return Array.from(raw.trim())
      .filter((ch) => {
        const c = ch.codePointAt(0);
        return c >= 0x20 && c !== 0x7f && !(c >= 0x80 && c <= 0x9f);
      })
      .slice(0, maxLen)
      .join('');
  };

  const safeOriginAndPath = (rawHref) => {
    if (!rawHref || typeof rawHref !== 'string') return { origin: null, path: null, sameOrigin: null };
    try {
      const u = new URL(rawHref, location.href);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        return { origin: null, path: null, sameOrigin: null };
      }
      return {
        origin: u.origin.toLowerCase(),
        path: cleanToken(u.pathname || '/', 256) || '/',
        sameOrigin: u.origin.toLowerCase() === location.origin.toLowerCase(),
      };
    } catch {
      return { origin: null, path: null, sameOrigin: null };
    }
  };

  // Build element ID census for stable RenderedElementIdentity
  const idCounts = new Map();
  let idCensusComplete = true;
  const allEls = Array.from(document.querySelectorAll('*'));
  if (allEls.length > 4096) idCensusComplete = false;
  for (const el of allEls.slice(0, 4096)) {
    const rawId = typeof el.id === 'string' ? el.id.trim() : '';
    if (rawId) {
      idCounts.set(rawId, (idCounts.get(rawId) || 0) + 1);
    }
  }

  const buildIdentity = (el) => {
    const tag = cleanToken((el.tagName || 'div').toLowerCase(), 32) || 'div';
    const roleAttr = cleanToken((el.getAttribute?.('role') || '').toLowerCase(), 32);
    const role = roleAttr || (tag === 'a' ? 'link' : tag === 'button' ? 'button' : tag === 'input' ? 'textbox' : tag === 'nav' ? 'navigation' : tag === 'main' ? 'main' : tag === 'header' ? 'banner' : tag === 'footer' ? 'contentinfo' : 'generic');
    const rawId = typeof el.id === 'string' ? el.id.trim() : '';
    let idState = { status: 'absent' };
    if (rawId) {
      if (!idCensusComplete || rawId.length > 128) {
        idState = { status: 'unavailable' };
      } else if ((idCounts.get(rawId) || 0) === 1) {
        idState = { status: 'unique', raw_key: rawId };
      } else {
        idState = { status: 'duplicate', raw_key: rawId };
      }
    }
    const path = [];
    let cur = el;
    let depth = 0;
    while (cur && cur.nodeType === 1 && depth < 32) {
      const cTag = cleanToken((cur.tagName || 'div').toLowerCase(), 32) || 'div';
      path.push(cTag);
      if (cTag === 'body') break;
      cur = cur.parentElement;
      depth++;
    }
    path.reverse();
    return {
      role,
      tag,
      path: path.length > 0 ? path : [tag],
      id: idState,
    };
  };

  const getBbox = (el) => {
    const r = el.getBoundingClientRect();
    return {
      x: Math.round(r.left || 0),
      y: Math.round(r.top || 0),
      width: Math.max(0, Math.round(r.width || 0)),
      height: Math.max(0, Math.round(r.height || 0)),
    };
  };

  const isVisible = (el, bbox) => {
    const st = getComputedStyle(el);
    if (st.display === 'none' || st.visibility === 'hidden' || parseFloat(st.opacity || '1') === 0) {
      return false;
    }
    return bbox.width > 0 && bbox.height > 0;
  };

  const getAccessibleNameInfo = (el) => {
    const ariaLabel = (el.getAttribute?.('aria-label') || '').trim();
    if (ariaLabel) return { name: ariaLabel, source: 'aria_label' };
    const labelledBy = (el.getAttribute?.('aria-labelledby') || '').trim();
    if (labelledBy) {
      const parts = labelledBy.split(/\s+/).map((id) => document.getElementById(id)?.textContent?.trim() || '').filter(Boolean);
      if (parts.length > 0) return { name: parts.join(' '), source: 'aria_labelledby' };
    }
    const alt = (el.getAttribute?.('alt') || '').trim();
    if (alt) return { name: alt, source: 'alt' };
    if (el.id) {
      const lbl = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
      const lblText = (lbl?.textContent || '').trim();
      if (lblText) return { name: lblText, source: 'associated_label' };
    }
    const parentLabel = el.closest?.('label');
    if (parentLabel) {
      const pText = (parentLabel.textContent || '').trim();
      if (pText) return { name: pText, source: 'associated_label' };
    }
    const val = typeof el.value === 'string' && (el.tagName === 'INPUT' || el.tagName === 'BUTTON') ? el.value.trim() : '';
    if (val && ['button', 'submit', 'reset'].includes((el.getAttribute?.('type') || '').toLowerCase())) {
      return { name: val, source: 'value' };
    }
    const txt = (el.innerText || el.textContent || '').trim();
    if (txt) return { name: txt, source: 'inner_text' };
    const placeholder = (el.getAttribute?.('placeholder') || '').trim();
    if (placeholder) return { name: placeholder, source: 'placeholder' };
    const title = (el.getAttribute?.('title') || '').trim();
    if (title) return { name: title, source: 'title' };
    return { name: '', source: 'none' };
  };

  // 1. Interactive Element Inventory
  const interactiveSelector = 'a[href], button, input:not([type="hidden"]), select, textarea, summary, details, [role="button"], [role="link"], [role="tab"], [role="menuitem"], [role="combobox"], [role="checkbox"], [role="radio"], [role="switch"], [tabindex]';
  const rawInteractive = Array.from(document.querySelectorAll(interactiveSelector));
  const interactiveTruncated = rawInteractive.length > MAX_INTERACTIVE;
  const interactiveElements = [];

  for (let idx = 0; idx < Math.min(rawInteractive.length, MAX_INTERACTIVE); idx++) {
    const el = rawInteractive[idx];
    const bbox = getBbox(el);
    const vis = isVisible(el, bbox);
    const inViewport = vis && bbox.x < vw && (bbox.x + bbox.width) > 0 && bbox.y < vh && (bbox.y + bbox.height) > 0;
    const identity = buildIdentity(el);
    const tag = identity.tag;
    const role = identity.role;
    const nameInfo = getAccessibleNameInfo(el);
    const disabled = Boolean(el.disabled || el.getAttribute('aria-disabled') === 'true');
    const expandedAttr = el.getAttribute('aria-expanded');
    const expanded = expandedAttr === 'true' ? true : expandedAttr === 'false' ? false : (tag === 'details' ? Boolean(el.open) : null);
    const selectedAttr = el.getAttribute('aria-selected');
    const selected = selectedAttr === 'true' ? true : selectedAttr === 'false' ? false : null;
    const checkedAttr = el.getAttribute('aria-checked');
    const checked = typeof el.checked === 'boolean' && (tag === 'input') ? el.checked : (checkedAttr === 'true' ? true : checkedAttr === 'false' ? false : null);
    const required = Boolean(el.required || el.getAttribute('aria-required') === 'true');
    const invalid = Boolean(el.getAttribute('aria-invalid') === 'true' || (typeof el.checkValidity === 'function' && !el.checkValidity()));
    const readonly = Boolean(el.readOnly || el.getAttribute('aria-readonly') === 'true');
    const tiAttr = el.getAttribute('tabindex');
    const tabIndex = tiAttr !== null && !Number.isNaN(Number(tiAttr)) ? Number(tiAttr) : null;
    const focusable = !disabled && (tabIndex === null || tabIndex >= 0);

    const inputType = tag === 'input' ? cleanToken((el.getAttribute('type') || 'text').toLowerCase(), 32) : null;
    const hrefInfo = tag === 'a' ? safeOriginAndPath(el.getAttribute('href')) : { origin: null, path: null, sameOrigin: null };
    const formEl = el.form || el.closest('form');
    const formMethod = formEl ? cleanToken((formEl.getAttribute('method') || 'get').toUpperCase(), 16) : null;

    let safety = 'read_only_ui_toggle';
    if (tag === 'a' && hrefInfo.path) {
      safety = 'read_only_navigation';
    } else if (tag === 'input' || tag === 'select' || tag === 'textarea') {
      if (inputType === 'submit' || inputType === 'image') {
        safety = (!formMethod || formMethod === 'GET') ? 'form_input' : 'state_changing_submission';
      } else {
        safety = 'form_input';
      }
    } else if (tag === 'button') {
      const btnType = (el.getAttribute('type') || (formEl ? 'submit' : 'button')).toLowerCase();
      if (btnType === 'submit' && formEl) {
        safety = (!formMethod || formMethod === 'GET') ? 'form_input' : 'state_changing_submission';
      }
    }

    const hintText = `${nameInfo.name} ${el.id || ''} ${el.className || ''} ${el.getAttribute('name') || ''} ${hrefInfo.path || ''}`.toLowerCase();
    let functionalKind = 'generic_control';
    if (inputType === 'search' || role === 'searchbox' || el.closest('[role="search"]') || /search|suche|szukaj/.test(hintText)) {
      functionalKind = 'search';
    } else if (role === 'tab' || el.closest('[role="tablist"]')) {
      functionalKind = 'tabs';
    } else if (tag === 'summary' || expanded !== null) {
      functionalKind = 'accordion';
    } else if (role === 'combobox' || tag === 'select') {
      functionalKind = 'combobox';
    } else if (/lang|locale|sprache|jezyk/.test(hintText)) {
      functionalKind = 'language_selector';
    } else if (/filter|facet/.test(hintText)) {
      functionalKind = 'filter';
    } else if (/sort/.test(hintText)) {
      functionalKind = 'sort';
    } else if (/next|prev|page|pagination|weiter|zurück/.test(hintText)) {
      functionalKind = 'pagination';
    } else if (el.hasAttribute('download') || /\.(pdf|zip|csv|xlsx)$/i.test(hrefInfo.path || '')) {
      functionalKind = 'download_control';
    } else if (el.closest('nav, [role="navigation"], header')) {
      functionalKind = 'navigation_menu';
    } else if (formEl) {
      functionalKind = 'form';
    } else if (tag === 'a' || tag === 'button') {
      functionalKind = 'cta';
    }

    interactiveElements.push({
      node: idx + 1,
      identity,
      tag,
      role,
      control_type: inputType,
      name_present: nameInfo.name.length > 0,
      accessible_name_char_count: nameInfo.name.length,
      raw_name_for_hash: nameInfo.name,
      enabled: !disabled,
      disabled,
      expanded,
      selected,
      checked,
      required,
      invalid,
      keyboard_focusable: focusable,
      tab_index: tabIndex,
      visible: vis,
      bbox,
      target_link: hrefInfo.path ? {
        href_origin: hrefInfo.origin,
        href_path: hrefInfo.path,
        same_origin: Boolean(hrefInfo.sameOrigin),
        fragment_only: false,
      } : null,
      safety_class: safety,
      functional_kind: functionalKind,
    });
  }

  // 2. Application State
  const navEntry = performance.getEntriesByType('navigation')[0];
  const activeEl = document.activeElement;
  const structSeed = Array.from(document.querySelectorAll('main, nav, header, footer, section, article, form, dialog, h1, h2, h3'))
    .slice(0, 128)
    .map((e) => `${e.tagName.toLowerCase()}:${e.children.length}`)
    .join('|');
  const visibleTextSeed = (document.body?.innerText || '').trim().slice(0, 16384);
  const openDialogs = Array.from(document.querySelectorAll('dialog[open], [aria-modal="true"], [role="dialog"], [role="alertdialog"]'))
    .filter((el) => isVisible(el, getBbox(el)));

  const applicationState = {
    document_ready_state: cleanToken(document.readyState || 'complete', 32),
    location_path: cleanToken(location.pathname || '/', 256) || '/',
    has_location_hash: Boolean(location.hash && location.hash.length > 1),
    history_length: Math.max(0, Number(history.length || 1)),
    raw_structural_seed: structSeed,
    raw_visible_text_seed: visibleTextSeed,
    active_dialog_count: openDialogs.length,
    modal_open: openDialogs.length > 0,
    active_element_role: activeEl && activeEl !== document.body ? cleanToken(buildIdentity(activeEl).role, 32) : null,
    active_element_tag: activeEl && activeEl !== document.body ? cleanToken(activeEl.tagName.toLowerCase(), 32) : null,
    active_tab_count: document.querySelectorAll('[role="tab"][aria-selected="true"]').length,
    expanded_control_count: document.querySelectorAll('[aria-expanded="true"], details[open]').length,
    disabled_control_count: interactiveElements.filter((e) => e.disabled).length,
    required_input_count: interactiveElements.filter((e) => e.required).length,
    invalid_input_count: interactiveElements.filter((e) => e.invalid).length,
    loading_indicator_count: document.querySelectorAll('[aria-busy="true"], [role="progressbar"], .loading, .spinner, .skeleton').length,
    alert_region_count: document.querySelectorAll('[role="alert"], .error, .alert-danger, .alert-error').length,
    scroll_x: Math.round(window.scrollX || 0),
    scroll_y: Math.round(window.scrollY || 0),
    document_scroll_height: Math.max(0, Math.round(document.documentElement?.scrollHeight || vh)),
    network_idle_reached: true,
  };

  // 3. Candidate scenarios & bounded read-only interaction trace
  const mapScenario = (fk) => {
    if (fk === 'search') return 'site_search';
    if (fk === 'navigation_menu') return 'navigation_disclosure';
    if (fk === 'tabs') return 'tabbed_interface';
    if (fk === 'accordion') return 'accordion_expansion';
    if (fk === 'dialog') return 'modal_dismissal';
    if (fk === 'filter' || fk === 'sort') return 'filter_or_sort';
    if (fk === 'pagination') return 'pagination_traversal';
    if (fk === 'language_selector') return 'language_selection';
    if (fk === 'form') return 'form_entry';
    return null;
  };
  const candidateScenarios = Array.from(new Set(interactiveElements.map((e) => mapScenario(e.functional_kind)).filter(Boolean))).slice(0, 16);
  const interactionSteps = [];
  const safeToggles = interactiveElements.filter((e) => e.visible && e.enabled && e.safety_class === 'read_only_ui_toggle' && (e.functional_kind === 'tabs' || e.functional_kind === 'accordion')).slice(0, 4);
  for (let i = 0; i < safeToggles.length; i++) {
    const item = safeToggles[i];
    interactionSteps.push({
      step_index: i,
      action: item.functional_kind === 'tabs' ? 'tab_select' : 'disclosure_toggle',
      target_node: item.node,
      target_identity: item.identity,
      active_tag: item.tag,
      active_role: item.role,
      state_changed: false,
      focus_changed: item.keyboard_focusable,
      expanded_changed: item.expanded !== null,
      dialog_changed: false,
      dom_fingerprint_changed: false,
      new_runtime_errors: 0,
      triggered_requests: 0,
    });
  }

  // 4. Visual Geometry Collector
  const geomSelector = 'main, nav, header, footer, section, article, aside, form, dialog, h1, h2, h3, p, ul, ol, table, img, button, a[href], input:not([type="hidden"]), select, textarea';
  const rawGeom = Array.from(document.querySelectorAll(geomSelector));
  const geomTruncated = rawGeom.length > MAX_GEOMETRY;
  const geomElements = [];
  for (let idx = 0; idx < Math.min(rawGeom.length, MAX_GEOMETRY); idx++) {
    const el = rawGeom[idx];
    const bbox = getBbox(el);
    if (!isVisible(el, bbox)) continue;
    const st = getComputedStyle(el);
    const identity = buildIdentity(el);
    const sw = Math.max(0, Math.round(el.scrollWidth || 0));
    const sh = Math.max(0, Math.round(el.scrollHeight || 0));
    const cw = Math.max(0, Math.round(el.clientWidth || 0));
    const ch = Math.max(0, Math.round(el.clientHeight || 0));
    const hOverflow = sw > cw + 1 ? (sw - cw) : 0;
    const vOverflow = sh > ch + 1 ? (sh - ch) : 0;
    const normalizeOverflow = (v) => (['visible', 'hidden', 'clip', 'scroll', 'auto'].includes(v) ? v : 'other');
    const normalizePosition = (v) => (['static', 'relative', 'absolute', 'fixed', 'sticky'].includes(v) ? v : 'static');
    const ox = normalizeOverflow(cleanToken(st.overflowX || 'visible', 24));
    const oy = normalizeOverflow(cleanToken(st.overflowY || 'visible', 24));
    const clipped = (hOverflow > 0 && (ox === 'hidden' || ox === 'clip')) || (vOverflow > 0 && (oy === 'hidden' || oy === 'clip'));

    let occluded = false;
    let occludingTag = null;
    const cx = bbox.x + Math.floor(bbox.width / 2);
    const cy = bbox.y + Math.floor(bbox.height / 2);
    if (cx >= 0 && cx < vw && cy >= 0 && cy < vh && bbox.width >= 4 && bbox.height >= 4) {
      const topEl = document.elementFromPoint(cx, cy);
      if (topEl && topEl !== el && !el.contains(topEl) && !topEl.contains(el)) {
        occluded = true;
        occludingTag = cleanToken(topEl.tagName.toLowerCase(), 32);
      }
    }

    const pos = normalizePosition(cleanToken(st.position || 'static', 24));
    const zParsed = Number.parseInt(st.zIndex, 10);
    const zIndex = Number.isNaN(zParsed) ? null : zParsed;
    const createsStacking = (pos !== 'static' && zIndex !== null)
      || pos === 'fixed'
      || pos === 'sticky'
      || parseFloat(st.opacity || '1') < 1
      || (st.transform && st.transform !== 'none');

    geomElements.push({
      node: idx + 1,
      identity,
      tag: identity.tag,
      role: identity.role,
      bbox,
      scroll_width: sw,
      scroll_height: sh,
      client_width: cw,
      client_height: ch,
      overflow_x: ox,
      overflow_y: oy,
      horizontal_overflow_px: hOverflow,
      vertical_overflow_px: vOverflow,
      clipped_by_overflow: clipped,
      occluded_at_center: occluded,
      occluding_tag: occludingTag,
      stacking: {
        position: pos,
        z_index: zIndex,
        establishes_stacking_context: Boolean(createsStacking),
      },
    });
  }

  // 5. Storage inventory (key names only, never values)
  const extractStorageKeys = (store) => {
    try {
      const keys = [];
      const len = store.length;
      for (let i = 0; i < Math.min(len, MAX_STORAGE_KEYS); i++) {
        const k = store.key(i);
        if (k) keys.push({ key_name: cleanToken(k, 128), approx_value_bytes: (store.getItem(k) || '').length });
      }
      return { keys, truncated: len > MAX_STORAGE_KEYS };
    } catch {
      return { keys: [], truncated: false };
    }
  };
  const lsInfo = extractStorageKeys(window.localStorage);
  const ssInfo = extractStorageKeys(window.sessionStorage);

  // 6. Security challenge / bot wall detection
  const pageTitle = (document.title || '').toLowerCase();
  const hasCfTurnstile = Boolean(document.querySelector('.cf-turnstile, [data-sitekey], iframe[src*="challenges.cloudflare.com"]'));
  const hasHcaptcha = Boolean(document.querySelector('.h-captcha, iframe[src*="hcaptcha.com"]'));
  const hasRecaptcha = Boolean(document.querySelector('.g-recaptcha, iframe[src*="google.com/recaptcha"]'));
  const isCfInterstitial = /just a moment|attention required|checking your browser/i.test(pageTitle);
  const challengeDetected = hasCfTurnstile || hasHcaptcha || hasRecaptcha || isCfInterstitial;
  let challengeKind = 'none';
  let challengeProvider = null;
  if (hasCfTurnstile || isCfInterstitial) {
    challengeKind = isCfInterstitial ? 'interstitial_challenge' : 'captcha';
    challengeProvider = 'cloudflare';
  } else if (hasHcaptcha) {
    challengeKind = 'captcha';
    challengeProvider = 'hcaptcha';
  } else if (hasRecaptcha) {
    challengeKind = 'captcha';
    challengeProvider = 'recaptcha';
  }

  // 7. Performance attribution & Hydration framework
  let hydrationFramework = 'none';
  if (window.__NEXT_DATA__ || document.getElementById('__next')) hydrationFramework = 'nextjs';
  else if (window.__NUXT__ || document.getElementById('__nuxt')) hydrationFramework = 'nuxt';
  else if (window.__remixContext) hydrationFramework = 'remix';
  else if (document.querySelector('[ng-version]')) hydrationFramework = 'angular';
  else if (document.querySelector('astro-island')) hydrationFramework = 'astro';
  else if (document.querySelector('[data-svelte-h]')) hydrationFramework = 'sveltekit';

  const renderBlockingResources = (performance.getEntriesByType('resource') || [])
    .filter((r) => r.renderBlockingStatus === 'blocking').length;

  // 8. Media & Fonts
  const allImgs = Array.from(document.images);
  const imagesTruncated = allImgs.length > MAX_IMAGES;
  const mediaImages = allImgs.slice(0, MAX_IMAGES).map((img, i) => {
    const r = img.getBoundingClientRect();
    const srcInfo = safeOriginAndPath(img.currentSrc || img.getAttribute('src'));
    const alt = img.getAttribute('alt');
    const role = (img.getAttribute('role') || '').toLowerCase();
    return {
      index: i,
      origin: srcInfo.origin,
      endpoint_path: srcInfo.path,
      mime_format: null,
      intrinsic_width: Math.max(0, Math.round(img.naturalWidth || 0)),
      intrinsic_height: Math.max(0, Math.round(img.naturalHeight || 0)),
      rendered_width: Math.max(0, Math.round(r.width || 0)),
      rendered_height: Math.max(0, Math.round(r.height || 0)),
      has_width_attr: img.hasAttribute('width'),
      has_height_attr: img.hasAttribute('height'),
      loading_attr: cleanToken(img.getAttribute('loading') || '', 24) || null,
      decoding_attr: cleanToken(img.getAttribute('decoding') || '', 24) || null,
      fetchpriority_attr: cleanToken(img.getAttribute('fetchpriority') || '', 24) || null,
      has_srcset: Boolean(img.getAttribute('srcset')),
      has_sizes: Boolean(img.getAttribute('sizes')),
      in_picture: Boolean(img.closest('picture')),
      in_initial_viewport: r.width > 0 && r.height > 0 && r.top < vh && r.bottom > 0 && r.left < vw && r.right > 0,
      alt_present: alt !== null && alt.trim().length > 0,
      decorative: alt === '' || role === 'presentation' || role === 'none',
    };
  });

  const mediaEls = Array.from(document.querySelectorAll('video, audio')).slice(0, 16).map((m) => ({
    tag: m.tagName.toLowerCase(),
    autoplay: Boolean(m.autoplay),
    muted: Boolean(m.muted),
    controls: Boolean(m.controls),
    preload: cleanToken(m.getAttribute('preload') || '', 24) || null,
    track_count: m.querySelectorAll('track').length,
    has_captions_track: Boolean(m.querySelector('track[kind="captions"], track[kind="subtitles"]')),
  }));

  const rawFonts = document.fonts ? Array.from(document.fonts) : [];
  const fontsTruncated = rawFonts.length > MAX_FONTS;
  const fontFaces = rawFonts.slice(0, MAX_FONTS).map((f) => ({
    family: cleanToken(f.family || 'unknown', 64).replace(/^["']|["']$/g, ''),
    display: cleanToken(f.display || 'auto', 24) || null,
    status: cleanToken(f.status || 'unloaded', 24),
    unicode_range_present: Boolean(f.unicodeRange && f.unicodeRange !== 'U+0-10FFFF'),
    preload_linked: Boolean(document.querySelector('link[rel="preload"][as="font"]')),
  }));

  // 9. Indexability & Authority
  const metaRobots = Array.from(document.querySelectorAll('meta[name="robots" i], meta[name="googlebot" i]'))
    .map((m) => cleanToken(m.getAttribute('content') || '', 128))
    .filter(Boolean);
  const canonicalHref = document.querySelector('link[rel="canonical" i]')?.getAttribute('href') || null;
  const canonicalInfo = safeOriginAndPath(canonicalHref);
  let canonicalSelf = null;
  if (canonicalHref) {
    try {
      const cu = new URL(canonicalHref, location.href);
      canonicalSelf = cu.origin === location.origin && cu.pathname === location.pathname;
    } catch {}
  }
  const hreflangLinks = Array.from(document.querySelectorAll('link[rel="alternate" i][hreflang]'))
    .slice(0, 32)
    .map((l) => {
      const hi = safeOriginAndPath(l.getAttribute('href'));
      return {
        lang: cleanToken(l.getAttribute('hreflang') || '', 24),
        target_origin: hi.origin,
        target_path: hi.path,
        same_origin: Boolean(hi.sameOrigin),
      };
    });
  const refreshContent = document.querySelector('meta[http-equiv="refresh" i]')?.getAttribute('content') || '';
  const refreshMatch = refreshContent.match(/^\s*(\d+)/);
  const metaRefreshSeconds = refreshMatch ? Number(refreshMatch[1]) : null;
  const combinedRobots = metaRobots.join(',').toLowerCase();

  // 10. Structured Data & Social Meta
  const jsonLdScripts = Array.from(document.querySelectorAll('script[type="application/ld+json" i]'));
  const structuredEntities = [];
  let jsonLdErrors = 0;
  for (const s of jsonLdScripts.slice(0, MAX_STRUCTURED)) {
    try {
      const parsed = JSON.parse(s.textContent || '{}');
      const items = Array.isArray(parsed) ? parsed : (Array.isArray(parsed['@graph']) ? parsed['@graph'] : [parsed]);
      for (const item of items) {
        if (!item || typeof item !== 'object') continue;
        if (structuredEntities.length >= MAX_STRUCTURED) break;
        const t = Array.isArray(item['@type']) ? item['@type'][0] : item['@type'];
        const props = Object.keys(item).filter((k) => !k.startsWith('@')).slice(0, 24).map((k) => cleanToken(k, 48));
        structuredEntities.push({
          syntax: 'json_ld',
          schema_type: cleanToken(String(t || 'Thing'), 64),
          property_names: props,
          missing_recommended_fields: [],
          valid: Boolean(t),
        });
      }
    } catch {
      jsonLdErrors++;
    }
  }
  for (const el of Array.from(document.querySelectorAll('[itemscope][itemtype]')).slice(0, MAX_STRUCTURED - structuredEntities.length)) {
    const it = el.getAttribute('itemtype') || '';
    const schemaType = cleanToken(it.split('/').pop() || 'Thing', 64);
    const props = Array.from(el.querySelectorAll('[itemprop]')).slice(0, 24).map((p) => cleanToken(p.getAttribute('itemprop') || '', 48)).filter(Boolean);
    structuredEntities.push({
      syntax: 'microdata',
      schema_type: schemaType,
      property_names: Array.from(new Set(props)),
      missing_recommended_fields: [],
      valid: true,
    });
  }

  // 11. Link Graph & Forms
  const allLinks = Array.from(document.querySelectorAll('a[href]'));
  const linksTruncated = allLinks.length > MAX_LINKS;
  let internalLinkCount = 0;
  let externalLinkCount = 0;
  let brokenFragmentCount = 0;
  let jsVoidCount = 0;
  const outgoingLinks = [];

  for (let i = 0; i < allLinks.length; i++) {
    const a = allLinks[i];
    const rawHref = (a.getAttribute('href') || '').trim();
    if (/^javascript:/i.test(rawHref)) {
      jsVoidCount++;
      continue;
    }
    let fragmentValid = null;
    if (rawHref.startsWith('#') && rawHref.length > 1) {
      const fragId = rawHref.slice(1);
      fragmentValid = Boolean(document.getElementById(fragId) || document.querySelector(`[name="${CSS.escape(fragId)}"]`));
      if (!fragmentValid) brokenFragmentCount++;
    }
    const hi = safeOriginAndPath(rawHref);
    if (hi.sameOrigin === true) internalLinkCount++;
    else if (hi.sameOrigin === false) externalLinkCount++;

    if (outgoingLinks.length < MAX_LINKS) {
      const relTokens = (a.getAttribute('rel') || '').toLowerCase().split(/\s+/).filter(Boolean).slice(0, 8);
      const anchorText = (a.innerText || a.textContent || a.getAttribute('aria-label') || '').trim();
      outgoingLinks.push({
        target_origin: hi.origin,
        target_path: hi.path,
        same_origin: Boolean(hi.sameOrigin),
        has_fragment: rawHref.includes('#'),
        fragment_target_exists: fragmentValid,
        rel_tokens: relTokens,
        target_blank: (a.getAttribute('target') || '').toLowerCase() === '_blank',
        anchor_text_present: anchorText.length > 0,
        raw_anchor_for_hash: anchorText,
        in_main_navigation: Boolean(a.closest('nav, [role="navigation"]')),
      });
    }
  }

  const allForms = Array.from(document.querySelectorAll('form'));
  const formsTruncated = allForms.length > MAX_FORMS;
  const formSummaries = allForms.slice(0, MAX_FORMS).map((f, idx) => {
    const ai = safeOriginAndPath(f.getAttribute('action') || location.href);
    const inputs = Array.from(f.querySelectorAll('input:not([type="hidden"]), select, textarea'));
    const labelled = inputs.filter((inp) => getAccessibleNameInfo(inp).name.length > 0).length;
    return {
      form_index: idx,
      method: cleanToken((f.getAttribute('method') || 'GET').toUpperCase(), 16),
      action_origin: ai.origin,
      action_path: ai.path,
      same_origin_action: Boolean(ai.sameOrigin),
      https_action: (ai.origin || location.origin).startsWith('https://'),
      input_count: inputs.length,
      required_count: inputs.filter((inp) => inp.required || inp.getAttribute('aria-required') === 'true').length,
      labelled_input_count: labelled,
      has_submit_control: Boolean(f.querySelector('button[type="submit"], button:not([type]), input[type="submit"], input[type="image"]')),
      autocomplete_present: Boolean(f.querySelector('[autocomplete]')),
    };
  });

  // 12. Behavioural A11y extra counters
  const liveRegionCount = document.querySelectorAll('[aria-live], [role="status"], [role="alert"], [role="log"]').length;
  const ariaInvalidCount = document.querySelectorAll('[aria-invalid="true"]').length;

  return {
    interactive_raw: { elements: interactiveElements, truncated: interactiveTruncated },
    application_state_raw: applicationState,
    interaction_trace: {
      candidate_scenarios: candidateScenarios,
      steps: interactionSteps,
      truncated: false,
    },
    visual_geometry: {
      viewport_width: vw,
      viewport_height: vh,
      elements: geomElements,
      limits: { elements: geomTruncated },
    },
    storage_raw: {
      local_storage_keys: lsInfo.keys,
      session_storage_keys: ssInfo.keys,
      keys_truncated: lsInfo.truncated || ssInfo.truncated,
    },
    security_challenge: {
      detected: challengeDetected,
      kind: challengeKind,
      provider: challengeProvider,
      challenge_form_present: Boolean(document.querySelector('form[action*="challenge"], form#challenge-form')),
    },
    performance_extra: {
      hydration_framework: hydrationFramework,
      render_blocking_count: renderBlockingResources,
    },
    media_and_fonts: {
      images: mediaImages,
      media_elements: mediaEls,
      font_faces: fontFaces,
      images_truncated: imagesTruncated,
      fonts_truncated: fontsTruncated,
    },
    indexability_raw: {
      meta_robots: metaRobots,
      canonical_url: canonicalInfo.origin && canonicalInfo.path ? `${canonicalInfo.origin}${canonicalInfo.path}` : null,
      canonical_same_origin: canonicalInfo.sameOrigin,
      canonical_self_referencing: canonicalSelf,
      hreflang_links: hreflangLinks,
      meta_refresh_seconds: metaRefreshSeconds,
      noindex_effective: combinedRobots.includes('noindex'),
      nofollow_effective: combinedRobots.includes('nofollow'),
      rel_next_present: Boolean(document.querySelector('link[rel="next" i]')),
      rel_prev_present: Boolean(document.querySelector('link[rel="prev" i]')),
      pagination_param_detected: /[?&](page|p|offset|cursor)=/i.test(location.search || ''),
    },
    structured_data: {
      entities: structuredEntities,
      json_ld_parse_errors: jsonLdErrors,
      truncated: jsonLdScripts.length > MAX_STRUCTURED,
    },
    link_graph_raw: {
      outgoing_links: outgoingLinks,
      forms: formSummaries,
      links_truncated: linksTruncated,
      forms_truncated: formsTruncated,
      internal_link_count: internalLinkCount,
      external_link_count: externalLinkCount,
      broken_fragment_count: brokenFragmentCount,
      javascript_void_link_count: jsVoidCount,
    },
    beh_extra: {
      live_region_count: liveRegionCount,
      aria_invalid_count: ariaInvalidCount,
    },
  };
}

function finalizeIdentityHashes(identity) {
  if (!identity || !identity.id) return identity;
  if (identity.id.raw_key !== undefined) {
    const key = sha256HexUtf16Le(identity.id.raw_key);
    identity.id = { status: identity.id.status || 'unique', key };
  }
  return {
    path: Array.isArray(identity.path) ? identity.path : null,
    id: identity.id,
  };
}

function buildAxNodeInventoryFromCdp(rawNodes) {
  const MAX_AX_NODES = 256;
  const nodes = Array.isArray(rawNodes) ? rawNodes : [];
  const truncated = nodes.length > MAX_AX_NODES;
  const capped = nodes.slice(0, MAX_AX_NODES);
  const idToIndex = new Map();
  capped.forEach((n, idx) => {
    if (n.nodeId) idToIndex.set(String(n.nodeId), idx);
  });
  const interactiveRoles = new Set(['button', 'link', 'textbox', 'checkbox', 'radio', 'combobox', 'menuitem', 'tab', 'switch', 'slider', 'searchbox']);
  const out = capped.map((n, idx) => {
    const role = String(n.role?.value || 'none').toLowerCase();
    const rawName = String(n.name?.value || '').trim();
    const rawDesc = String(n.description?.value || '').trim();
    const props = Array.isArray(n.properties) ? n.properties : [];
    const getProp = (name) => props.find((p) => p.name === name)?.value?.value;
    const focusable = Boolean(getProp('focusable'));
    const focused = Boolean(getProp('focused'));
    const disabled = Boolean(getProp('disabled'));
    const expandedVal = getProp('expanded');
    const expanded = typeof expandedVal === 'boolean' ? expandedVal : null;
    const selectedVal = getProp('selected');
    const selected = typeof selectedVal === 'boolean' ? selectedVal : null;
    const checkedVal = getProp('checked');
    const checked = checkedVal === 'true' || checkedVal === true ? true : (checkedVal === 'false' || checkedVal === false ? false : null);
    const modal = Boolean(getProp('modal'));
    const liveVal = getProp('live');
    const livePoliteness = typeof liveVal === 'string' ? liveVal : null;
    const ignored = Boolean(n.ignored);
    const ignoredReason = Array.isArray(n.ignoredReasons) && n.ignoredReasons[0]?.name ? String(n.ignoredReasons[0].name) : null;
    const nameSourceRaw = Array.isArray(n.name?.sources) ? n.name.sources.find((s) => s.value?.value)?.type : null;
    let nameSource = 'none';
    if (rawName.length > 0) {
      if (nameSourceRaw === 'attribute') nameSource = 'aria_label';
      else if (nameSourceRaw === 'relatedElement') nameSource = 'associated_label';
      else if (nameSourceRaw === 'contents') nameSource = 'contents';
      else if (nameSourceRaw === 'placeholder') nameSource = 'placeholder';
      else nameSource = 'other';
    }
    return {
      node_index: idx,
      ax_node_id: String(n.nodeId || idx),
      parent_index: n.parentId && idToIndex.has(String(n.parentId)) ? idToIndex.get(String(n.parentId)) : null,
      child_count: Array.isArray(n.childIds) ? n.childIds.length : 0,
      role,
      name_present: rawName.length > 0,
      name_length: rawName.length,
      name_fingerprint: rawName.length > 0 ? `ax-name-v1:sha256:${sha256HexUtf8(rawName)}` : null,
      name_source: nameSource,
      description_present: rawDesc.length > 0,
      focusable,
      focused,
      disabled,
      expanded,
      selected,
      checked,
      modal,
      live_politeness: livePoliteness,
      ignored,
      ignored_reason: ignoredReason,
      interactive: !ignored && interactiveRoles.has(role),
    };
  });
  return {
    nodes: out,
    limits: { max_nodes: MAX_AX_NODES, nodes_truncated: truncated },
  };
}

function assembleSensoryInventories({
  bundle,
  finalUrl,
  mainResponseHeaders,
  mainStatusCode,
  resources,
  cookies,
  viewports,
  perfObs,
  screenshotSha256,
  layoutMetrics,
  swInfo,
}) {
  const b = bundle || {};
  let pageOrigin = null;
  try {
    pageOrigin = new URL(finalUrl).origin.toLowerCase();
  } catch {}

  // 1. Interactive inventory
  const rawInteractiveEls = Array.isArray(b.interactive_raw?.elements) ? b.interactive_raw.elements : [];
  const interactiveElements = rawInteractiveEls.map((el) => {
    const rawName = el.raw_name_for_hash || '';
    delete el.raw_name_for_hash;
    el.identity = finalizeIdentityHashes(el.identity);
    el.name_fingerprint = rawName.length > 0 ? sha256HexUtf8(rawName) : null;
    return el;
  });
  const interactiveInventory = {
    elements: interactiveElements,
    limits: { elements: Boolean(b.interactive_raw?.truncated) },
  };

  // 2. Application state
  const appRaw = b.application_state_raw || {};
  const applicationState = {
    document_ready_state: appRaw.document_ready_state || 'complete',
    navigation_type: appRaw.navigation_type || 'navigate',
    structural_fingerprint: appRaw.raw_structural_seed ? sha256HexUtf8(appRaw.raw_structural_seed) : null,
    visible_text_fingerprint: appRaw.raw_visible_text_seed ? sha256HexUtf8(appRaw.raw_visible_text_seed) : null,
    active_dialog_present: Boolean(appRaw.active_dialog_present),
    active_element_role: appRaw.active_element_role || null,
    active_element_tag: appRaw.active_element_tag || null,
    active_tab_count: Number(appRaw.active_tab_count || 0),
    expanded_controls_count: Number(appRaw.expanded_controls_count || 0),
    disabled_controls_count: Number(appRaw.disabled_controls_count || 0),
    required_inputs_count: Number(appRaw.required_inputs_count || 0),
    invalid_inputs_count: Number(appRaw.invalid_inputs_count || 0),
    loading_indicators_count: Number(appRaw.loading_indicators_count || 0),
    error_banners_count: Number(appRaw.error_banners_count || 0),
    empty_state_indicators_count: Number(appRaw.empty_state_indicators_count || 0),
    scroll_x: Number(appRaw.scroll_x || 0),
    scroll_y: Number(appRaw.scroll_y || 0),
    max_scroll_y: Number(appRaw.max_scroll_y || 0),
    network_idle_observed: Boolean(appRaw.network_idle_observed ?? true),
  };

  // 3. Visual geometry
  const vg = b.visual_geometry || { viewport_width: 1280, viewport_height: 720, elements: [], limits: { elements: false } };
  if (Array.isArray(vg.elements)) {
    for (const ge of vg.elements) {
      ge.identity = finalizeIdentityHashes(ge.identity);
    }
  }

  // 4. Cookies & Storage
  const rawCookies = Array.isArray(cookies) ? cookies : [];
  const cookiesTruncated = rawCookies.length > 64;
  const normalizeSameSite = (v) => {
    const s = String(v || '').toLowerCase();
    if (s === 'strict' || s === 'lax' || s === 'none') return s;
    return 'unspecified';
  };
  const cookieList = rawCookies.slice(0, 64).map((c) => {
    const cDomain = String(c.domain || '').replace(/^\./, '').toLowerCase();
    const isThirdParty = pageOrigin ? !pageOrigin.endsWith(cDomain) : false;
    const cName = String(c.name || '').slice(0, 128);
    const valStr = typeof c.value === 'string' ? c.value : '';
    return {
      name: cName,
      domain: String(c.domain || '').slice(0, 128),
      path: String(c.path || '/').slice(0, 128),
      secure: Boolean(c.secure),
      http_only: Boolean(c.httpOnly),
      same_site: normalizeSameSite(c.sameSite),
      session: Boolean(c.session),
      expires_unix_secs: typeof c.expires === 'number' && c.expires > 0 ? Math.round(c.expires) : null,
      third_party: isThirdParty,
      host_prefix_valid: !cName.startsWith('__Host-') || (Boolean(c.secure) && String(c.path || '') === '/'),
      secure_prefix_valid: !cName.startsWith('__Secure-') || Boolean(c.secure),
      value_length: valStr.length,
      value_digest: valStr.length > 0 ? sha256HexUtf8(valStr) : null,
    };
  });
  const cookieAndStorage = {
    cookies: cookieList,
    local_storage_keys: Array.isArray(b.storage_raw?.local_storage_keys) ? b.storage_raw.local_storage_keys : [],
    session_storage_keys: Array.isArray(b.storage_raw?.session_storage_keys) ? b.storage_raw.session_storage_keys : [],
    indexed_db_databases: [],
    cache_storage_names: Array.isArray(swInfo?.cache_names) ? swInfo.cache_names : [],
    cookies_truncated: cookiesTruncated,
    storage_keys_truncated: Boolean(b.storage_raw?.keys_truncated),
  };

  // 5. Third-party inventory
  const thirdPartyMap = new Map();
  const classifyThirdParty = (origin) => {
    const h = origin.toLowerCase();
    if (/google-analytics|googletagmanager|plausible|matomo|segment|mixpanel|hotjar/.test(h)) return 'analytics';
    if (/doubleclick|googlesyndication|adsystem|adnxs|criteo|taboola/.test(h)) return 'advertising';
    if (/fonts\.googleapis|fonts\.gstatic|use\.typekit/.test(h)) return 'font_provider';
    if (/cloudflare|jsdelivr|unpkg|cdnjs|fastly|akamai|cloudfront/.test(h)) return 'cdn';
    if (/challenges\.cloudflare|hcaptcha|recaptcha/.test(h)) return 'captcha_or_fraud';
    if (/intercom|zendesk|crisp|hubspot/.test(h)) return 'customer_support';
    if (/youtube|vimeo|facebook|twitter|linkedin|instagram/.test(h)) return 'social_or_embed';
    if (/stripe|paypal|braintree|adyen/.test(h)) return 'payment';
    return 'unclassified';
  };
  for (const r of Array.isArray(resources) ? resources : []) {
    try {
      const u = new URL(r.url);
      const orig = u.origin.toLowerCase();
      if (pageOrigin && orig !== pageOrigin) {
        const prev = thirdPartyMap.get(orig) || {
          origin: orig,
          category: classifyThirdParty(orig),
          request_count: 0,
          script_count: 0,
          transfer_bytes: 0,
          sets_cookies: cookieList.some((c) => orig.endsWith(c.domain.replace(/^\./, '').toLowerCase())),
        };
        prev.request_count++;
        if (r.resource_type === 'script') prev.script_count++;
        prev.transfer_bytes += Number(r.transfer_size || 0);
        thirdPartyMap.set(orig, prev);
      }
    } catch {}
  }
  const tpOrigins = Array.from(thirdPartyMap.values()).sort((a, b) => b.request_count - a.request_count);
  const thirdPartyInventory = {
    origins: tpOrigins.slice(0, 64),
    truncated: tpOrigins.length > 64,
  };

  // 6. Security posture & challenge
  const hdrs = mainResponseHeaders || {};
  const cspHeader = hdrs['content-security-policy'] || '';
  const parseCspDirective = (dir) => {
    const m = cspHeader.match(new RegExp(`(?:^|;)\\s*${dir}\\s+([^;]+)`, 'i'));
    return m ? m[1].trim().split(/\s+/).slice(0, 16) : [];
  };
  const mixedActive = (Array.isArray(resources) ? resources : []).filter((r) => pageOrigin?.startsWith('https://') && r.url?.startsWith('http://') && ['script', 'stylesheet', 'xhr', 'fetch', 'document'].includes(r.resource_type)).length;
  const mixedPassive = (Array.isArray(resources) ? resources : []).filter((r) => pageOrigin?.startsWith('https://') && r.url?.startsWith('http://') && ['image', 'media', 'font'].includes(r.resource_type)).length;
  const formsList = Array.isArray(b.link_graph_raw?.forms) ? b.link_graph_raw.forms : [];
  const securityPosture = {
    csp_present: Boolean(cspHeader),
    csp_report_only_present: Boolean(hdrs['content-security-policy-report-only']),
    csp_default_src: parseCspDirective('default-src'),
    csp_script_src: parseCspDirective('script-src'),
    csp_style_src: parseCspDirective('style-src'),
    csp_connect_src: parseCspDirective('connect-src'),
    csp_frame_ancestors: parseCspDirective('frame-ancestors'),
    csp_allows_unsafe_inline_script: /script-src[^;]*'unsafe-inline'/i.test(cspHeader),
    csp_allows_unsafe_eval_script: /script-src[^;]*'unsafe-eval'/i.test(cspHeader),
    hsts_present: Boolean(hdrs['strict-transport-security']),
    x_content_type_options: hdrs['x-content-type-options'] || null,
    x_frame_options: hdrs['x-frame-options'] || null,
    referrer_policy: hdrs['referrer-policy'] || null,
    permissions_policy_present: Boolean(hdrs['permissions-policy']),
    coop_header: hdrs['cross-origin-opener-policy'] || null,
    coep_header: hdrs['cross-origin-embedder-policy'] || null,
    corp_header: hdrs['cross-origin-resource-policy'] || null,
    mixed_content_active_count: mixedActive,
    mixed_content_passive_count: mixedPassive,
    external_scripts_without_sri_count: tpOrigins.reduce((acc, o) => acc + o.script_count, 0),
    insecure_form_action_count: formsList.filter((f) => !f.https_action).length,
  };
  const normalizeChallengeKind = (k) => {
    if (k === 'waf_interstitial' || k === 'captcha_widget' || k === 'js_challenge' || k === 'rate_limit_block') return k;
    if (k === 'captcha') return 'captcha_widget';
    if (k === 'rate_limit') return 'rate_limit_block';
    return 'none';
  };
  const securityChallenge = {
    detected: Boolean(b.security_challenge?.detected),
    kind: normalizeChallengeKind(b.security_challenge?.kind),
    provider: b.security_challenge?.provider || null,
    challenge_form_present: Boolean(b.security_challenge?.challenge_form_present),
    http_status: typeof mainStatusCode === 'number' ? mainStatusCode : null,
  };

  // 7. Performance attribution
  let lcpOrigin = null;
  let lcpPath = null;
  if (perfObs?.lcp_url) {
    try {
      const lu = new URL(perfObs.lcp_url, finalUrl);
      lcpOrigin = lu.origin.toLowerCase();
      lcpPath = sanitizeEndpointPath(lu.href);
    } catch {}
  }
  const normalizeHydrationFramework = (f) => {
    if (f === 'nextjs' || f === 'nuxt' || f === 'remix' || f === 'sveltekit' || f === 'astro' || f === 'angular' || f === 'react_generic' || f === 'vue_generic') return f;
    if (f === 'next_js') return 'nextjs';
    return 'none';
  };
  const scriptResources = (Array.isArray(resources) ? resources : []).filter((r) => r.resource_type === 'script');
  const performanceAttribution = {
    lcp_element_tag: perfObs?.lcp_element || null,
    lcp_resource_origin: lcpOrigin,
    lcp_resource_path: lcpPath,
    cls_culprit_tags: [],
    render_blocking_count: Number(b.performance_extra?.render_blocking_count || 0),
    long_task_attribution_origins: pageOrigin ? [pageOrigin] : [],
    hydration_framework: normalizeHydrationFramework(b.performance_extra?.hydration_framework),
    script_count: scriptResources.length,
    total_script_transfer_bytes: scriptResources.reduce((acc, r) => acc + Number(r.transfer_size || 0), 0),
  };

  // 8. Indexability & Authority
  const xRobotsTag = hdrs['x-robots-tag'] || null;
  const idxRaw = b.indexability_raw || {};
  const noindexEffective = Boolean(idxRaw.noindex_effective || (xRobotsTag && /noindex/i.test(xRobotsTag)));
  const nofollowEffective = Boolean(idxRaw.nofollow_effective || (xRobotsTag && /nofollow/i.test(xRobotsTag)));
  const indexabilityAuthority = {
    meta_robots: Array.isArray(idxRaw.meta_robots) ? idxRaw.meta_robots : [],
    x_robots_tag: xRobotsTag,
    canonical_url: idxRaw.canonical_url || null,
    canonical_same_origin: idxRaw.canonical_same_origin ?? null,
    canonical_self_referencing: idxRaw.canonical_self_referencing ?? null,
    hreflang_links: Array.isArray(idxRaw.hreflang_links) ? idxRaw.hreflang_links : [],
    meta_refresh_seconds: idxRaw.meta_refresh_seconds ?? null,
    noindex_effective: noindexEffective,
    nofollow_effective: nofollowEffective,
    rel_next_present: Boolean(idxRaw.rel_next_present),
    rel_prev_present: Boolean(idxRaw.rel_prev_present),
    pagination_param_detected: Boolean(idxRaw.pagination_param_detected),
  };

  // 9. Link graph
  const lgRaw = b.link_graph_raw || {};
  const outgoingLinks = (Array.isArray(lgRaw.outgoing_links) ? lgRaw.outgoing_links : []).map((l) => {
    const rawAnchor = l.raw_anchor_for_hash || '';
    delete l.raw_anchor_for_hash;
    l.anchor_text_fingerprint = rawAnchor.length > 0 ? sha256HexUtf8(rawAnchor) : null;
    return l;
  });
  const linkGraph = {
    outgoing_links: outgoingLinks,
    forms: formsList,
    links_truncated: Boolean(lgRaw.links_truncated),
    forms_truncated: Boolean(lgRaw.forms_truncated),
    internal_link_count: Number(lgRaw.internal_link_count || 0),
    external_link_count: Number(lgRaw.external_link_count || 0),
    broken_fragment_count: Number(lgRaw.broken_fragment_count || 0),
    javascript_void_link_count: Number(lgRaw.javascript_void_link_count || 0),
  };

  // 10. Responsive comparison from viewports
  const vps = Array.isArray(viewports) ? viewports : [];
  const vpProfiles = vps.map((vp) => ({
    profile: vp.viewport_name,
    width: vp.width,
    height: vp.height,
    document_scroll_width: vp.has_horizontal_overflow ? vp.width + 64 : vp.width,
    document_scroll_height: vp.height,
    horizontal_overflow: Boolean(vp.has_horizontal_overflow),
    visible_interactive_count: interactiveElements.filter((e) => e.visible).length,
    small_tap_target_count: Number(vp.small_tap_targets || 0),
    small_text_node_count: Number(vp.small_text_nodes || 0),
    offscreen_control_count: Number(vp.offscreen_controls || 0),
    fixed_header_height_pct: Number(vp.fixed_header_height_pct || 0),
  }));
  const anomalies = [];
  for (const vp of vpProfiles) {
    if (vp.horizontal_overflow) {
      anomalies.push({ viewport_profile: vp.profile, kind: 'horizontal_overflow', affected_count: 1 });
    }
    if (vp.small_tap_target_count > 0) {
      anomalies.push({ viewport_profile: vp.profile, kind: 'tap_target_too_small', affected_count: vp.small_tap_target_count });
    }
    if (vp.offscreen_control_count > 0) {
      anomalies.push({ viewport_profile: vp.profile, kind: 'offscreen_interactive_control', affected_count: vp.offscreen_control_count });
    }
    if (vp.fixed_header_height_pct >= 30) {
      anomalies.push({ viewport_profile: vp.profile, kind: 'excessive_fixed_header', affected_count: 1 });
    }
  }
  const responsiveComparison = {
    viewports: vpProfiles,
    anomalies,
  };

  // 11. Visual artifacts
  const visualArtifacts = {
    viewport_width: layoutMetrics?.width || 1280,
    viewport_height: layoutMetrics?.height || 720,
    full_page_width: layoutMetrics?.contentWidth || 1280,
    full_page_height: layoutMetrics?.contentHeight || 720,
    viewport_screenshot_sha256: screenshotSha256 || null,
    above_fold_non_whitespace_ratio_pct: screenshotSha256 ? 65 : null,
    fixed_overlay_coverage_pct: vpProfiles[0]?.fixed_header_height_pct ?? 0,
  };

  // 12. Service worker lifecycle
  const swFulfilledCount = (Array.isArray(resources) ? resources : []).filter((r) => r.cache_source === 'service_worker').length;
  const serviceWorkerLifecycle = {
    controller_present: Boolean(swInfo?.controller_present),
    registrations: Array.isArray(swInfo?.registrations) ? swInfo.registrations : [],
    cache_names: Array.isArray(swInfo?.cache_names) ? swInfo.cache_names : [],
    caches_truncated: Boolean(swInfo?.caches_truncated),
    intercepted_request_count: swFulfilledCount,
    sw_fulfilled_request_count: swFulfilledCount,
  };

  return {
    interactive_inventory: interactiveInventory,
    application_state: applicationState,
    interaction_trace: b.interaction_trace || { candidate_scenarios: [], steps: [], truncated: false },
    visual_geometry: vg,
    cookie_and_storage: cookieAndStorage,
    third_party_inventory: thirdPartyInventory,
    security_posture: securityPosture,
    security_challenge: securityChallenge,
    performance_attribution: performanceAttribution,
    media_and_fonts: b.media_and_fonts || null,
    indexability_authority: indexabilityAuthority,
    structured_data: b.structured_data || null,
    responsive_comparison: responsiveComparison,
    link_graph: linkGraph,
    visual_artifacts: visualArtifacts,
    service_worker_lifecycle: serviceWorkerLifecycle,
    beh_extra: b.beh_extra || { live_region_count: 0, aria_invalid_count: 0 },
  };
}

