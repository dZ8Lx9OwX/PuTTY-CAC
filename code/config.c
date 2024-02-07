/*
 * config.c - the platform-independent parts of the PuTTY
 * configuration box.
 */

#include <assert.h>
#include <stdlib.h>

#include "putty.h"
#include "dialog.h"
#include "storage.h"
#include "tree234.h"
#ifdef PUTTY_CAC
#include "cert_common.h"
#endif // PUTTY_CAC

#define PRINTER_DISABLED_STRING "无输出(禁止打印)"

#define HOST_BOX_TITLE "主机名或IP地址"
#define PORT_BOX_TITLE "端口"

void conf_radiobutton_handler(dlgcontrol *ctrl, dlgparam *dlg,
                              void *data, int event)
{
    int button;
    Conf *conf = (Conf *)data;

    /*
     * For a standard radio button set, the context parameter gives
     * the primary key (CONF_foo), and the extra data per button
     * gives the value the target field should take if that button
     * is the one selected.
     */
    if (event == EVENT_REFRESH) {
        int val = conf_get_int(conf, ctrl->context.i);
        for (button = 0; button < ctrl->radio.nbuttons; button++)
            if (val == ctrl->radio.buttondata[button].i)
                break;
        /* We expected that `break' to happen, in all circumstances. */
        assert(button < ctrl->radio.nbuttons);
        dlg_radiobutton_set(ctrl, dlg, button);
    } else if (event == EVENT_VALCHANGE) {
        button = dlg_radiobutton_get(ctrl, dlg);
        assert(button >= 0 && button < ctrl->radio.nbuttons);
        conf_set_int(conf, ctrl->context.i,
                     ctrl->radio.buttondata[button].i);
    }
}

void conf_radiobutton_bool_handler(dlgcontrol *ctrl, dlgparam *dlg,
                                   void *data, int event)
{
    int button;
    Conf *conf = (Conf *)data;

    /*
     * Same as conf_radiobutton_handler, but using conf_set_bool in
     * place of conf_set_int, because it's dealing with a bool-typed
     * config option.
     */
    if (event == EVENT_REFRESH) {
        int val = conf_get_bool(conf, ctrl->context.i);
        for (button = 0; button < ctrl->radio.nbuttons; button++)
            if (val == ctrl->radio.buttondata[button].i)
                break;
        /* We expected that `break' to happen, in all circumstances. */
        assert(button < ctrl->radio.nbuttons);
        dlg_radiobutton_set(ctrl, dlg, button);
    } else if (event == EVENT_VALCHANGE) {
        button = dlg_radiobutton_get(ctrl, dlg);
        assert(button >= 0 && button < ctrl->radio.nbuttons);
        conf_set_bool(conf, ctrl->context.i,
                      ctrl->radio.buttondata[button].i);
    }
}

#define CHECKBOX_INVERT (1<<30)
void conf_checkbox_handler(dlgcontrol *ctrl, dlgparam *dlg,
                           void *data, int event)
{
    int key;
    bool invert;
    Conf *conf = (Conf *)data;

    /*
     * For a standard checkbox, the context parameter gives the
     * primary key (CONF_foo), optionally ORed with CHECKBOX_INVERT.
     */
    key = ctrl->context.i;
    if (key & CHECKBOX_INVERT) {
        key &= ~CHECKBOX_INVERT;
        invert = true;
    } else
        invert = false;

    /*
     * C lacks a logical XOR, so the following code uses the idiom
     * (!a ^ !b) to obtain the logical XOR of a and b. (That is, 1
     * iff exactly one of a and b is nonzero, otherwise 0.)
     */

    if (event == EVENT_REFRESH) {
        bool val = conf_get_bool(conf, key);
        dlg_checkbox_set(ctrl, dlg, (!val ^ !invert));
    } else if (event == EVENT_VALCHANGE) {
        conf_set_bool(conf, key, !dlg_checkbox_get(ctrl,dlg) ^ !invert);
    }
}

const struct conf_editbox_handler_type conf_editbox_str = {.type = EDIT_STR};
const struct conf_editbox_handler_type conf_editbox_int = {.type = EDIT_INT};

void conf_editbox_handler(dlgcontrol *ctrl, dlgparam *dlg,
                          void *data, int event)
{
    /*
     * The standard edit-box handler expects the main `context' field
     * to contain the primary key. The secondary `context2' field is a
     * pointer to the struct conf_editbox_handler_type defined in
     * putty.h.
     */
    int key = ctrl->context.i;
    const struct conf_editbox_handler_type *type = ctrl->context2.cp;
    Conf *conf = (Conf *)data;

    if (type->type == EDIT_STR) {
        if (event == EVENT_REFRESH) {
            char *field = conf_get_str(conf, key);
            dlg_editbox_set(ctrl, dlg, field);
        } else if (event == EVENT_VALCHANGE) {
            char *field = dlg_editbox_get(ctrl, dlg);
            conf_set_str(conf, key, field);
            sfree(field);
        }
    } else {
        if (event == EVENT_REFRESH) {
            char str[80];
            int value = conf_get_int(conf, key);
            if (type->type == EDIT_INT)
                sprintf(str, "%d", value);
            else
                sprintf(str, "%g", (double)value / type->denominator);
            dlg_editbox_set(ctrl, dlg, str);
        } else if (event == EVENT_VALCHANGE) {
            char *str = dlg_editbox_get(ctrl, dlg);
            if (type->type == EDIT_INT)
                conf_set_int(conf, key, atoi(str));
            else
                conf_set_int(conf, key, (int)(type->denominator * atof(str)));
            sfree(str);
        }
    }
}

void conf_filesel_handler(dlgcontrol *ctrl, dlgparam *dlg,
                          void *data, int event)
{
    int key = ctrl->context.i;
    Conf *conf = (Conf *)data;

    if (event == EVENT_REFRESH) {
        dlg_filesel_set(
            ctrl, dlg, conf_get_filename(conf, key));
    } else if (event == EVENT_VALCHANGE) {
        Filename *filename = dlg_filesel_get(ctrl, dlg);
        conf_set_filename(conf, key, filename);
        filename_free(filename);
    }
}

void conf_fontsel_handler(dlgcontrol *ctrl, dlgparam *dlg,
                          void *data, int event)
{
    int key = ctrl->context.i;
    Conf *conf = (Conf *)data;

    if (event == EVENT_REFRESH) {
        dlg_fontsel_set(
            ctrl, dlg, conf_get_fontspec(conf, key));
    } else if (event == EVENT_VALCHANGE) {
        FontSpec *fontspec = dlg_fontsel_get(ctrl, dlg);
        conf_set_fontspec(conf, key, fontspec);
        fontspec_free(fontspec);
    }
}

static void config_host_handler(dlgcontrol *ctrl, dlgparam *dlg,
                                void *data, int event)
{
    Conf *conf = (Conf *)data;

    /*
     * This function works just like the standard edit box handler,
     * only it has to choose the control's label and text from two
     * different places depending on the protocol.
     */
    if (event == EVENT_REFRESH) {
        if (conf_get_int(conf, CONF_protocol) == PROT_SERIAL) {
            /*
             * This label text is carefully chosen to contain an n,
             * since that's the shortcut for the host name control.
             */
            dlg_label_change(ctrl, dlg, "串行线");
            dlg_editbox_set(ctrl, dlg, conf_get_str(conf, CONF_serline));
        } else {
            dlg_label_change(ctrl, dlg, HOST_BOX_TITLE);
            dlg_editbox_set(ctrl, dlg, conf_get_str(conf, CONF_host));
        }
    } else if (event == EVENT_VALCHANGE) {
        char *s = dlg_editbox_get(ctrl, dlg);
        if (conf_get_int(conf, CONF_protocol) == PROT_SERIAL)
            conf_set_str(conf, CONF_serline, s);
        else
            conf_set_str(conf, CONF_host, s);
        sfree(s);
    }
}

static void config_port_handler(dlgcontrol *ctrl, dlgparam *dlg,
                                void *data, int event)
{
    Conf *conf = (Conf *)data;
    char buf[80];

    /*
     * This function works similarly to the standard edit box handler,
     * only it has to choose the control's label and text from two
     * different places depending on the protocol.
     */
    if (event == EVENT_REFRESH) {
        if (conf_get_int(conf, CONF_protocol) == PROT_SERIAL) {
            /*
             * This label text is carefully chosen to contain a p,
             * since that's the shortcut for the port control.
             */
            dlg_label_change(ctrl, dlg, "波特率");
            sprintf(buf, "%d", conf_get_int(conf, CONF_serspeed));
        } else {
            dlg_label_change(ctrl, dlg, PORT_BOX_TITLE);
            if (conf_get_int(conf, CONF_port) != 0)
                sprintf(buf, "%d", conf_get_int(conf, CONF_port));
            else
                /* Display an (invalid) port of 0 as blank */
                buf[0] = '\0';
        }
        dlg_editbox_set(ctrl, dlg, buf);
    } else if (event == EVENT_VALCHANGE) {
        char *s = dlg_editbox_get(ctrl, dlg);
        int i = atoi(s);
        sfree(s);

        if (conf_get_int(conf, CONF_protocol) == PROT_SERIAL)
            conf_set_int(conf, CONF_serspeed, i);
        else
            conf_set_int(conf, CONF_port, i);
    }
}

struct hostport {
    dlgcontrol *host, *port, *protradio, *protlist;
    bool mid_refresh;
};

/*
 * Shared handler for protocol radio-button and drop-list controls.
 * Handles the interaction of those two controls, and also changes
 * the setting of the port box to match the protocol if necessary,
 * and refreshes both host and port boxes when switching to/from the
 * serial backend.
 */
static void config_protocols_handler(dlgcontrol *ctrl, dlgparam *dlg,
                                     void *data, int event)
{
    Conf *conf = (Conf *)data;
    int curproto = conf_get_int(conf, CONF_protocol);
    struct hostport *hp = (struct hostport *)ctrl->context.p;

    if (event == EVENT_REFRESH) {
        /*
         * Refresh the states of the controls from Conf.
         *
         * When refreshing these controls, we have to watch out for
         * re-entrancy: because there are two controls involved, the
         * refresh is not atomic, so the VALCHANGE and/or SELCHANGE
         * callbacks resulting from our updates here might cause other
         * settings here to change unwantedly. (E.g. setting the list
         * selection shouldn't trigger the SELCHANGE side effect of
         * selecting the Other radio button; setting the radio button
         * to Other here shouldn't have the side effect of selecting
         * whatever protocol is _currently_ selected in the list box,
         * if we haven't selected the right one yet.)
         */
        hp->mid_refresh = true;

        if (ctrl == hp->protradio) {
            /* Available buttons were set up when control was created.
             * Just select one of them, possibly. */
            for (int button = 0; button < ctrl->radio.nbuttons; button++)
                /* The final button is "Other:". If we reach that one, the
                 * current protocol must be in the drop list, so we should
                 * select the "Other:" button. */
                if (curproto == ctrl->radio.buttondata[button].i ||
                    button == ctrl->radio.nbuttons-1) {
                    dlg_radiobutton_set(ctrl, dlg, button);
                    break;
                }
        } else if (ctrl == hp->protlist) {
            int curentry = -1;
            dlg_update_start(ctrl, dlg);
            dlg_listbox_clear(ctrl, dlg);
            assert(n_ui_backends > 0 && n_ui_backends < PROTOCOL_LIMIT);
            for (size_t i = n_ui_backends;
                 i < PROTOCOL_LIMIT && backends[i]; i++) {
                dlg_listbox_addwithid(ctrl, dlg,
                                      backends[i]->displayname_tc,
                                      backends[i]->protocol);
                if (backends[i]->protocol == curproto)
                    curentry = i - n_ui_backends;
            }
            if (curentry > 0) {
                /*
                 * The currently configured protocol is one of the
                 * list-box ones, so select it in protlist.
                 *
                 * (The corresponding refresh event for protradio
                 * should have selected the "Other:" radio button, to
                 * keep things consistent.)
                 */
                dlg_listbox_select(ctrl, dlg, curentry);
            } else {
                /*
                 * If the currently configured protocol is one of the
                 * radio buttons, we must still ensure *something* is
                 * selected in the list box. The sensible default is
                 * the first list element, which be_*.c ought to have
                 * arranged to be the 'runner-up' in protocol
                 * popularity out of the ones relegated to the list
                 * box.
                 *
                 * We don't make much effort to retain the state of
                 * the list box when it doesn't correspond to an
                 * actual protocol. So it's easy for this case to be
                 * reached as a side effect of other actions, e.g.
                 * loading a saved session that has a radio-button
                 * protocol configured.
                 */
                dlg_listbox_select(ctrl, dlg, 0);
            }
            dlg_update_done(ctrl, dlg);
        }

        hp->mid_refresh = false;
    } else if (!hp->mid_refresh) {
        /*
         * Potentially update Conf from the states of the controls.
         */
        int newproto = curproto;

        if (event == EVENT_VALCHANGE && ctrl == hp->protradio) {
            int button = dlg_radiobutton_get(ctrl, dlg);
            assert(button >= 0 && button < ctrl->radio.nbuttons);
            if (ctrl->radio.buttondata[button].i == -1) {
                /*
                 * The 'Other' radio button was selected, which means we
                 * have to set CONF_protocol based on the currently
                 * selected list box entry.
                 *
                 * (We conditionalise this on there _being_ a selected
                 * list box entry. I hope the case where nothing is
                 * selected can't actually come up except during
                 * initialisation, and I also hope that hp->mid_session
                 * will prevent that case from getting here. But as a
                 * last-ditch fallback, this if statement should at least
                 * guarantee that we don't pass a nonsense value to
                 * dlg_listbox_getid.)
                 */
                int i = dlg_listbox_index(hp->protlist, dlg);
                if (i >= 0)
                    newproto = dlg_listbox_getid(hp->protlist, dlg, i);
            } else {
                newproto = ctrl->radio.buttondata[button].i;
            }
        } else if (event == EVENT_SELCHANGE && ctrl == hp->protlist) {
            int i = dlg_listbox_index(ctrl, dlg);
            if (i >= 0) {
                newproto = dlg_listbox_getid(ctrl, dlg, i);
                /* Select the "Other" radio button, too */
                dlg_radiobutton_set(hp->protradio, dlg,
                                    hp->protradio->radio.nbuttons-1);
            }
        }

        if (newproto != curproto) {
            conf_set_int(conf, CONF_protocol, newproto);

            const struct BackendVtable *cvt = backend_vt_from_proto(curproto);
            const struct BackendVtable *nvt = backend_vt_from_proto(newproto);
            assert(cvt);
            assert(nvt);
            /*
             * Iff the user hasn't changed the port from the old
             * protocol's default, update it with the new protocol's
             * default.
             *
             * (This includes a "default" of 0, implying that there is
             * no sensible default for that protocol; in this case
             * it's displayed as a blank.)
             *
             * This helps with the common case of tabbing through the
             * controls in order and setting a non-default port before
             * getting to the protocol; we want that non-default port
             * to be preserved.
             */
            int port = conf_get_int(conf, CONF_port);
            if (port == cvt->default_port)
                conf_set_int(conf, CONF_port, nvt->default_port);

            dlg_refresh(hp->host, dlg);
            dlg_refresh(hp->port, dlg);
        }
    }
}

static void loggingbuttons_handler(dlgcontrol *ctrl, dlgparam *dlg,
                                   void *data, int event)
{
    int button;
    Conf *conf = (Conf *)data;
    /* This function works just like the standard radio-button handler,
     * but it has to fall back to "no logging" in situations where the
     * configured logging type isn't applicable.
     */
    if (event == EVENT_REFRESH) {
        int logtype = conf_get_int(conf, CONF_logtype);

        for (button = 0; button < ctrl->radio.nbuttons; button++)
            if (logtype == ctrl->radio.buttondata[button].i)
                break;

        /* We fell off the end, so we lack the configured logging type */
        if (button == ctrl->radio.nbuttons) {
            button = 0;
            conf_set_int(conf, CONF_logtype, LGTYP_NONE);
        }
        dlg_radiobutton_set(ctrl, dlg, button);
    } else if (event == EVENT_VALCHANGE) {
        button = dlg_radiobutton_get(ctrl, dlg);
        assert(button >= 0 && button < ctrl->radio.nbuttons);
        conf_set_int(conf, CONF_logtype, ctrl->radio.buttondata[button].i);
    }
}

static void numeric_keypad_handler(dlgcontrol *ctrl, dlgparam *dlg,
                                   void *data, int event)
{
    int button;
    Conf *conf = (Conf *)data;
    /*
     * This function works much like the standard radio button
     * handler, but it has to handle two fields in Conf.
     */
    if (event == EVENT_REFRESH) {
        if (conf_get_bool(conf, CONF_nethack_keypad))
            button = 2;
        else if (conf_get_bool(conf, CONF_app_keypad))
            button = 1;
        else
            button = 0;
        assert(button < ctrl->radio.nbuttons);
        dlg_radiobutton_set(ctrl, dlg, button);
    } else if (event == EVENT_VALCHANGE) {
        button = dlg_radiobutton_get(ctrl, dlg);
        assert(button >= 0 && button < ctrl->radio.nbuttons);
        if (button == 2) {
            conf_set_bool(conf, CONF_app_keypad, false);
            conf_set_bool(conf, CONF_nethack_keypad, true);
        } else {
            conf_set_bool(conf, CONF_app_keypad, (button != 0));
            conf_set_bool(conf, CONF_nethack_keypad, false);
        }
    }
}

static void cipherlist_handler(dlgcontrol *ctrl, dlgparam *dlg,
                               void *data, int event)
{
    Conf *conf = (Conf *)data;
    if (event == EVENT_REFRESH) {
        int i;

        static const struct { const char *s; int c; } ciphers[] = {
            { "ChaCha20 (仅限SSH-2)",   CIPHER_CHACHA20 },
            { "AES-GCM  (仅限SSH-2)",   CIPHER_AESGCM },
            { "3DES",                   CIPHER_3DES },
            { "Blowfish",               CIPHER_BLOWFISH },
            { "DES",                    CIPHER_DES },
            { "AES      (仅限SSH-2)",   CIPHER_AES },
            { "Arcfour  (仅限SSH-2)",   CIPHER_ARCFOUR },
            { "-- 以下为警告选项 --",   CIPHER_WARN }
        };

        /* Set up the "selected ciphers" box. */
        /* (cipherlist assumed to contain all ciphers) */
        dlg_update_start(ctrl, dlg);
        dlg_listbox_clear(ctrl, dlg);
        for (i = 0; i < CIPHER_MAX; i++) {
            int c = conf_get_int_int(conf, CONF_ssh_cipherlist, i);
            int j;
            const char *cstr = NULL;
            for (j = 0; j < (sizeof ciphers) / (sizeof ciphers[0]); j++) {
                if (ciphers[j].c == c) {
                    cstr = ciphers[j].s;
                    break;
                }
            }
            dlg_listbox_addwithid(ctrl, dlg, cstr, c);
        }
        dlg_update_done(ctrl, dlg);

    } else if (event == EVENT_VALCHANGE) {
        int i;

        /* Update array to match the list box. */
        for (i=0; i < CIPHER_MAX; i++)
            conf_set_int_int(conf, CONF_ssh_cipherlist, i,
                             dlg_listbox_getid(ctrl, dlg, i));
    }
}

#ifndef NO_GSSAPI
static void gsslist_handler(dlgcontrol *ctrl, dlgparam *dlg,
                            void *data, int event)
{
    Conf *conf = (Conf *)data;
    if (event == EVENT_REFRESH) {
        int i;

        dlg_update_start(ctrl, dlg);
        dlg_listbox_clear(ctrl, dlg);
        for (i = 0; i < ngsslibs; i++) {
            int id = conf_get_int_int(conf, CONF_ssh_gsslist, i);
            assert(id >= 0 && id < ngsslibs);
            dlg_listbox_addwithid(ctrl, dlg, gsslibnames[id], id);
        }
        dlg_update_done(ctrl, dlg);

    } else if (event == EVENT_VALCHANGE) {
        int i;

        /* Update array to match the list box. */
        for (i=0; i < ngsslibs; i++)
            conf_set_int_int(conf, CONF_ssh_gsslist, i,
                             dlg_listbox_getid(ctrl, dlg, i));
    }
}
#endif

static void kexlist_handler(dlgcontrol *ctrl, dlgparam *dlg,
                            void *data, int event)
{
    Conf *conf = (Conf *)data;
    if (event == EVENT_REFRESH) {
        int i;

        static const struct { const char *s; int k; } kexes[] = {
            { "Diffie-Hellman group 1  (1024位)",  KEX_DHGROUP1 },
            { "Diffie-Hellman group 14 (2048位)", KEX_DHGROUP14 },
            { "Diffie-Hellman group 15 (3072位)", KEX_DHGROUP15 },
            { "Diffie-Hellman group 16 (4096位)", KEX_DHGROUP16 },
            { "Diffie-Hellman group 17 (6144位)", KEX_DHGROUP17 },
            { "Diffie-Hellman group 18 (8192位)", KEX_DHGROUP18 },
            { "Diffie-Hellman group exchange",      KEX_DHGEX },
            { "RSA-based key exchange",             KEX_RSA },
            { "ECDH key exchange",                  KEX_ECDH },
            { "NTRU Prime/Curve25519 hybrid kex", KEX_NTRU_HYBRID },
            { "-- 以下为警告选项 --",              KEX_WARN }
        };

        /* Set up the "kex preference" box. */
        /* (kexlist assumed to contain all algorithms) */
        dlg_update_start(ctrl, dlg);
        dlg_listbox_clear(ctrl, dlg);
        for (i = 0; i < KEX_MAX; i++) {
            int k = conf_get_int_int(conf, CONF_ssh_kexlist, i);
            int j;
            const char *kstr = NULL;
            for (j = 0; j < (sizeof kexes) / (sizeof kexes[0]); j++) {
                if (kexes[j].k == k) {
                    kstr = kexes[j].s;
                    break;
                }
            }
            dlg_listbox_addwithid(ctrl, dlg, kstr, k);
        }
        dlg_update_done(ctrl, dlg);

    } else if (event == EVENT_VALCHANGE) {
        int i;

        /* Update array to match the list box. */
        for (i=0; i < KEX_MAX; i++)
            conf_set_int_int(conf, CONF_ssh_kexlist, i,
                             dlg_listbox_getid(ctrl, dlg, i));
    }
}

static void hklist_handler(dlgcontrol *ctrl, dlgparam *dlg,
                           void *data, int event)
{
    Conf *conf = (Conf *)data;
    if (event == EVENT_REFRESH) {
        int i;

        static const struct { const char *s; int k; } hks[] = {
            { "Ed25519",               HK_ED25519 },
            { "Ed448",                 HK_ED448 },
            { "ECDSA",                 HK_ECDSA },
            { "DSA",                   HK_DSA },
            { "RSA",                   HK_RSA },
            { "-- 以下为警告选项 --",  HK_WARN }
        };

        /* Set up the "host key preference" box. */
        /* (hklist assumed to contain all algorithms) */
        dlg_update_start(ctrl, dlg);
        dlg_listbox_clear(ctrl, dlg);
        for (i = 0; i < HK_MAX; i++) {
            int k = conf_get_int_int(conf, CONF_ssh_hklist, i);
            int j;
            const char *kstr = NULL;
            for (j = 0; j < lenof(hks); j++) {
                if (hks[j].k == k) {
                    kstr = hks[j].s;
                    break;
                }
            }
            dlg_listbox_addwithid(ctrl, dlg, kstr, k);
        }
        dlg_update_done(ctrl, dlg);

    } else if (event == EVENT_VALCHANGE) {
        int i;

        /* Update array to match the list box. */
        for (i=0; i < HK_MAX; i++)
            conf_set_int_int(conf, CONF_ssh_hklist, i,
                             dlg_listbox_getid(ctrl, dlg, i));
    }
}

static void printerbox_handler(dlgcontrol *ctrl, dlgparam *dlg,
                               void *data, int event)
{
    Conf *conf = (Conf *)data;
    if (event == EVENT_REFRESH) {
        int nprinters, i;
        printer_enum *pe;
        const char *printer;

        dlg_update_start(ctrl, dlg);
        /*
         * Some backends may wish to disable the drop-down list on
         * this edit box. Be prepared for this.
         */
        if (ctrl->editbox.has_list) {
            dlg_listbox_clear(ctrl, dlg);
            dlg_listbox_add(ctrl, dlg, PRINTER_DISABLED_STRING);
            pe = printer_start_enum(&nprinters);
            for (i = 0; i < nprinters; i++)
                dlg_listbox_add(ctrl, dlg, printer_get_name(pe, i));
            printer_finish_enum(pe);
        }
        printer = conf_get_str(conf, CONF_printer);
        if (!printer)
            printer = PRINTER_DISABLED_STRING;
        dlg_editbox_set(ctrl, dlg, printer);
        dlg_update_done(ctrl, dlg);
    } else if (event == EVENT_VALCHANGE) {
        char *printer = dlg_editbox_get(ctrl, dlg);
        if (!strcmp(printer, PRINTER_DISABLED_STRING))
            printer[0] = '\0';
        conf_set_str(conf, CONF_printer, printer);
        sfree(printer);
    }
}

static void codepage_handler(dlgcontrol *ctrl, dlgparam *dlg,
                             void *data, int event)
{
    Conf *conf = (Conf *)data;
    if (event == EVENT_REFRESH) {
        int i;
        const char *cp, *thiscp;
        dlg_update_start(ctrl, dlg);
        thiscp = cp_name(decode_codepage(conf_get_str(conf,
                                                      CONF_line_codepage)));
        dlg_listbox_clear(ctrl, dlg);
        for (i = 0; (cp = cp_enumerate(i)) != NULL; i++)
            dlg_listbox_add(ctrl, dlg, cp);
        dlg_editbox_set(ctrl, dlg, thiscp);
        conf_set_str(conf, CONF_line_codepage, thiscp);
        dlg_update_done(ctrl, dlg);
    } else if (event == EVENT_VALCHANGE) {
        char *codepage = dlg_editbox_get(ctrl, dlg);
        conf_set_str(conf, CONF_line_codepage,
                     cp_name(decode_codepage(codepage)));
        sfree(codepage);
    }
}

static void sshbug_handler(dlgcontrol *ctrl, dlgparam *dlg,
                           void *data, int event)
{
    Conf *conf = (Conf *)data;
    if (event == EVENT_REFRESH) {
        /*
         * We must fetch the previously configured value from the Conf
         * before we start modifying the drop-down list, otherwise the
         * spurious SELCHANGE we trigger in the process will overwrite
         * the value we wanted to keep.
         */
        int oldconf = conf_get_int(conf, ctrl->context.i);
        dlg_update_start(ctrl, dlg);
        dlg_listbox_clear(ctrl, dlg);
        dlg_listbox_addwithid(ctrl, dlg, "自动", AUTO);
        dlg_listbox_addwithid(ctrl, dlg, "关闭", FORCE_OFF);
        dlg_listbox_addwithid(ctrl, dlg, "开启", FORCE_ON);
        switch (oldconf) {
          case AUTO:      dlg_listbox_select(ctrl, dlg, 0); break;
          case FORCE_OFF: dlg_listbox_select(ctrl, dlg, 1); break;
          case FORCE_ON:  dlg_listbox_select(ctrl, dlg, 2); break;
        }
        dlg_update_done(ctrl, dlg);
    } else if (event == EVENT_SELCHANGE) {
        int i = dlg_listbox_index(ctrl, dlg);
        if (i < 0)
            i = AUTO;
        else
            i = dlg_listbox_getid(ctrl, dlg, i);
        conf_set_int(conf, ctrl->context.i, i);
    }
}

static void sshbug_handler_manual_only(dlgcontrol *ctrl, dlgparam *dlg,
                                       void *data, int event)
{
    /*
     * This is just like sshbug_handler, except that there's no 'Auto'
     * option. Used for bug workaround flags that can't be
     * autodetected, and have to be manually enabled if they're to be
     * used at all.
     */
    Conf *conf = (Conf *)data;
    if (event == EVENT_REFRESH) {
        int oldconf = conf_get_int(conf, ctrl->context.i);
        dlg_update_start(ctrl, dlg);
        dlg_listbox_clear(ctrl, dlg);
        dlg_listbox_addwithid(ctrl, dlg, "关闭", FORCE_OFF);
        dlg_listbox_addwithid(ctrl, dlg, "开启", FORCE_ON);
        switch (oldconf) {
          case FORCE_OFF: dlg_listbox_select(ctrl, dlg, 0); break;
          case FORCE_ON:  dlg_listbox_select(ctrl, dlg, 1); break;
        }
        dlg_update_done(ctrl, dlg);
    } else if (event == EVENT_SELCHANGE) {
        int i = dlg_listbox_index(ctrl, dlg);
        if (i < 0)
            i = FORCE_OFF;
        else
            i = dlg_listbox_getid(ctrl, dlg, i);
        conf_set_int(conf, ctrl->context.i, i);
    }
}

struct sessionsaver_data {
    dlgcontrol *editbox, *listbox, *loadbutton, *savebutton, *delbutton;
    dlgcontrol *okbutton, *cancelbutton;
    struct sesslist sesslist;
    bool midsession;
    char *savedsession;     /* the current contents of ssd->editbox */
};

#ifdef PUTTY_CAC
struct cert_data {
	dlgcontrol* cert_set_pkcs_button, * cert_set_fido_button, * cert_set_capi_button, * cert_clear_button, * cert_view_button,
		* cert_thumbprint_text, * cert_copy_clipboard_button, * cert_enable_auth, * cert_auth_checkbox;
};

void cert_event_handler(dlgcontrol* ctrl, dlgparam* dlg, void* data, int event)
{
	Conf* conf = (Conf*)data;
	struct cert_data* certd = (struct cert_data*)ctrl->context.p;

	// use the clear button initialization to prepopulate the thumbprint field
	if (ctrl == certd->cert_clear_button && event == EVENT_REFRESH)
	{
		char* szCert = conf_get_str(conf, CONF_cert_fingerprint);
		if (cert_is_certpath(szCert))
		{
			dlg_text_set(certd->cert_thumbprint_text, dlg, szCert);
		}
	}

	// handle copy clipboard button press
	if (ctrl == certd->cert_copy_clipboard_button && event == EVENT_ACTION)
	{
		char* szCert = conf_get_str(conf, CONF_cert_fingerprint);
		char* szKeyString = cert_key_string(szCert);
		if (szKeyString == NULL) return;
        write_aclip(CLIP_SYSTEM, szKeyString, strlen(szKeyString), true);
		sfree(szKeyString);
	}

	// handle view clipboard button press
	if (ctrl == certd->cert_view_button && event == EVENT_ACTION)
	{
		char* szCert = conf_get_str(conf, CONF_cert_fingerprint);
		cert_display_cert(szCert, NULL);
	}

	// handle certificate clear button press
	if (ctrl == certd->cert_clear_button && event == EVENT_ACTION)
	{
		dlg_text_set(certd->cert_thumbprint_text, dlg, "<已清除证书/密钥选定项>");
		conf_set_str(conf, CONF_cert_fingerprint, "");
		conf_set_bool(conf, CONF_cert_attempt_auth, 0);
		dlg_checkbox_set(certd->cert_auth_checkbox, dlg, 0);
	}

	// handle capi certificate set button press
	if (ctrl == certd->cert_set_capi_button && event == EVENT_ACTION)
	{
		char* szCert = cert_prompt(IDEN_CAPI, FALSE, NULL);
		if (szCert == NULL) return;
		conf_set_str(conf, CONF_cert_fingerprint, szCert);
		conf_set_bool(conf, CONF_cert_attempt_auth, 1);
		dlg_checkbox_set(certd->cert_auth_checkbox, dlg, 1);
		dlg_text_set(certd->cert_thumbprint_text, dlg, szCert);
		sfree(szCert);
	}

	// handle pkcs certificate set button press
	if (ctrl == certd->cert_set_pkcs_button && event == EVENT_ACTION)
	{
		char* szCert = cert_prompt(IDEN_PKCS, FALSE, NULL);
		if (szCert == NULL) return;
		conf_set_str(conf, CONF_cert_fingerprint, szCert);
		conf_set_bool(conf, CONF_cert_attempt_auth, 1);
		dlg_checkbox_set(certd->cert_auth_checkbox, dlg, 1);
		*strrchr(szCert, '=') = '\0';
		dlg_text_set(certd->cert_thumbprint_text, dlg, szCert);
		sfree(szCert);
	}

	// handle fido certificate set button press
	if (ctrl == certd->cert_set_fido_button && event == EVENT_ACTION)
	{
		char* szCert = cert_prompt(IDEN_FIDO, FALSE, NULL);
		if (szCert == NULL) return;
		conf_set_str(conf, CONF_cert_fingerprint, szCert);
		conf_set_bool(conf, CONF_cert_attempt_auth, 1);
		dlg_checkbox_set(certd->cert_auth_checkbox, dlg, 1);
		dlg_text_set(certd->cert_thumbprint_text, dlg, szCert);
		sfree(szCert);
	}
}

struct fido_data {
	dlgcontrol* fido_create_key_button, * fido_delete_key_button, * fido_import_key_button, * fido_import_ssh_button,
        * fido_clear_key_button, * fido_algo_combobox, * fido_display_text, * fido_app_text, * fido_verification_radio, * fido_resident_radio;
};

void fido_event_handler(dlgcontrol* ctrl, dlgparam* dlg, void* data, int event)
{

	Conf* conf = (Conf*)data;
	struct fido_data* fidod = (struct fido_data*)ctrl->context.p;
	static const char* szAlgTable[] = {
		"ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521",
		"ssh-ed25519"
	};

	// handle fido key clear button press
	if (ctrl == fidod->fido_clear_key_button && event == EVENT_ACTION)
	{
		fido_clear_keys();
	}

	// handle fido key import button press
	if (ctrl == fidod->fido_import_key_button && event == EVENT_ACTION)
	{
		fido_import_keys();
	}

    // handle fido ssh key import button press
    if (ctrl == fidod->fido_import_ssh_button && event == EVENT_ACTION)
    {
        char * szAppId = fido_import_openssh_key();
        if (szAppId != NULL) 
        {
            // alert user of success and ask about assignment
            if (MessageBoxW(NULL, L"FIDO OpenSSH密钥导入成功" \
                L"并且已添加到FIDO缓存中。是否要将密钥分配给当前会话？？",
                L"FIDO OpenSSH密钥导入成功", MB_SYSTEMMODAL | MB_ICONQUESTION | MB_YESNO) == IDYES)
            {
                char* szCert = dupprintf("FIDO:%s", szAppId);
                conf_set_str(conf, CONF_cert_fingerprint, szCert);
                conf_set_bool(conf, CONF_cert_attempt_auth, 1);
                sfree(szCert);
            }
            sfree(szAppId);
        }
        else
        {
            MessageBoxW(NULL, L"未选择文件或无法读取所选文件。",
                L"FIDO OpenSSH密钥导入失败", MB_SYSTEMMODAL | MB_ICONERROR | MB_OK);
        }
    }

	// handle fido key create button press
	if (ctrl == fidod->fido_create_key_button && event == EVENT_ACTION)
	{
		// special alert about unusual types
		const char* szAlgId = szAlgTable[dlg_listbox_index(fidod->fido_algo_combobox, dlg)];
		if ((strcmp(szAlgId, "ecdsa-sha2-nistp384") == 0 || strcmp(szAlgId, "ecdsa-sha2-nistp521") == 0) &&
			MessageBoxW(NULL, L"PuTTY CAC支持所选算法，但大多数安全令牌不支持。" \
				L"因此，即使您输入了正确的PIN码，密钥创建仍可能会失败，或者您可能会" \
				L"在创建过程中看到重复的、无法解析的PIN提示。您是否还要继续？？",
				L"FIDO密钥类型警告", MB_SYSTEMMODAL | MB_ICONQUESTION | MB_YESNO) != IDYES) return;

		// display name
		char* szDisplayName = dlg_editbox_get(fidod->fido_display_text, dlg);
		if (szDisplayName == NULL || strlen(szDisplayName) == 0) {
			MessageBoxW(NULL, L"The value provided for display name is not valid. " \
				L"This value cannot be blank. " \
				L"Please check this value and try again.",
				L"FIDO Key Creation Parameters Invalid", MB_SYSTEMMODAL | MB_ICONERROR | MB_OK);
			return;
		}

		// sanity check on parameters
		char* szAppId = dlg_editbox_get(fidod->fido_app_text, dlg);
		if (szAppId == NULL || strstr(szAppId, "ssh:") != szAppId)
		{
			MessageBoxW(NULL, L"为应用程序名称提供的值无效。" \
				L"出于兼容性原因，此值必须以'ssh:'开头。" \
				L"请检查此值，然后重试。",
				L"FIDO 密钥创建参数无效", MB_SYSTEMMODAL | MB_ICONERROR | MB_OK);
			return;
		}

		// first see if a duplicate key exists
		char* szCertDupCheck = dupprintf("FIDO:%s", szAppId);
		PCERT_CONTEXT pCert = NULL;
		HCERTSTORE hCertStore = NULL;
		BOOL bKeyExists = cert_load_cert(szCertDupCheck, &pCert, &hCertStore);
		sfree(szCertDupCheck);
		if (bKeyExists)
		{
			CertFreeCertificateContext(pCert);
			CertCloseStore(hCertStore, 0);
			if (MessageBoxW(NULL, L"具有此名称的FIDO键似乎已经存在。" \
				L"PuTTY CAC可能无法确定要使用哪个密钥。是否确实要继续？？",
				L"检测到FIDO重复密钥", MB_SYSTEMMODAL | MB_ICONQUESTION | MB_YESNO) != IDYES) return;
		}

		// fetch options from resident key and verification boxes
		int bResidentKey = (dlg_radiobutton_get(fidod->fido_resident_radio, dlg) == 0);
		int bVerificationRequired = (dlg_radiobutton_get(fidod->fido_verification_radio, dlg) == 1);

		// attempt to create key
		if (fido_create_key(szAlgId, szDisplayName, szAppId, bResidentKey, bVerificationRequired))
		{
			// alert user of success and ask about assignment
			if (MessageBoxW(NULL, L"FIDO密钥创建成功，并且已添加到FIDO缓存中。" \
				L"是否要将新密钥分配给当前会话？？",
				L"FIDO密钥创建成功", MB_SYSTEMMODAL | MB_ICONQUESTION | MB_YESNO) == IDYES)
			{
				char* szCert = dupprintf("FIDO:%s", szAppId);
				conf_set_str(conf, CONF_cert_fingerprint, szCert);
				conf_set_bool(conf, CONF_cert_attempt_auth, 1);
				sfree(szCert);
			}
		}
		else MessageBoxW(NULL, L"PuTTY无法在令牌上创建密钥。请验证" \
			L"是否使用了兼容的令牌。您也可能输入了错误的PIN，" \
			L"或者令牌可能不支持所选的算法/参数。",
			L"FIDO密钥创建失败", MB_SYSTEMMODAL | MB_ICONERROR | MB_OK);

		sfree(szAppId);
	}

	// handle fido key delete button press
	if (ctrl == fidod->fido_delete_key_button && event == EVENT_ACTION)
	{
		char* szCert = cert_prompt(IDEN_FIDO, FALSE,
			L"选择要删除的FIDO密钥。如果这是一个驻留密钥，" \
			L"它也将从令牌中删除。");
		if (szCert == NULL) return;

		fido_delete_key(szCert);
		sfree(szCert);
	}

	// handle key algorithm key combo box population
	if (ctrl == fidod->fido_algo_combobox && event == EVENT_REFRESH)
	{
		dlg_update_start(ctrl, dlg);
		dlg_listbox_clear(ctrl, dlg);
		for (int iIndex = 0; iIndex < _countof(szAlgTable); iIndex++)
			dlg_listbox_add(ctrl, dlg, szAlgTable[iIndex]);
		dlg_listbox_select(ctrl, dlg, 0);
		dlg_update_done(ctrl, dlg);
	}

	// default text for display name
	if (ctrl == fidod->fido_display_text && event == EVENT_REFRESH)
	{
		dlg_editbox_set(ctrl, dlg, "SSH FIDO Key");
	}

	// default text for application name
	if (ctrl == fidod->fido_app_text && event == EVENT_REFRESH)
	{
		dlg_editbox_set(ctrl, dlg, "ssh:");
	}

	// handle default radio bottom selection
	if (ctrl == fidod->fido_resident_radio && event == EVENT_REFRESH ||
		ctrl == fidod->fido_verification_radio && event == EVENT_REFRESH)
	{
		dlg_radiobutton_set(ctrl, dlg, 0);
	}
}

struct capi_data {
	dlgcontrol* capi_create_key_button, * capi_delete_key_button, * capi_provider_radio, * capi_algo_combobox,
		* capi_name_text, * capi_no_expired_checkbox, * capi_smartcard_only_checkbox, * capi_trusted_certs_checkbox,
		* cert_store_button;
};

void capi_event_handler(dlgcontrol* ctrl, dlgparam* dlg, void* data, int event)
{
	Conf* conf = (Conf*)data;

	struct capi_data* capid = (struct capi_data*)ctrl->context.p;
	static const char* szAlgTable[] = {
		"rsa-1024",
		"rsa-2048",
		"rsa-3072",
		"rsa-4096",
		"ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521"
	};

	// handle certificate filter - ignore expired
	if (ctrl == capid->capi_no_expired_checkbox && event == EVENT_REFRESH)
		dlg_checkbox_set(ctrl, dlg, cert_ignore_expired_certs(CERT_QUERY));
	if (ctrl == capid->capi_no_expired_checkbox && event == EVENT_VALCHANGE)
		cert_ignore_expired_certs(dlg_checkbox_get(ctrl, dlg));

	// handle certificate filter - smartcard only expired
	if (ctrl == capid->capi_smartcard_only_checkbox && event == EVENT_REFRESH)
		dlg_checkbox_set(ctrl, dlg, cert_smartcard_certs_only(CERT_QUERY));
	if (ctrl == capid->capi_smartcard_only_checkbox && event == EVENT_VALCHANGE)
		cert_smartcard_certs_only(dlg_checkbox_get(ctrl, dlg));

	// handle certificate filter - trusted only
	if (ctrl == capid->capi_trusted_certs_checkbox && event == EVENT_REFRESH)
		dlg_checkbox_set(ctrl, dlg, cert_trusted_certs_only(CERT_QUERY));
	if (ctrl == capid->capi_trusted_certs_checkbox && event == EVENT_VALCHANGE)
		cert_trusted_certs_only(dlg_checkbox_get(ctrl, dlg));

	// handle key algorithm key combo box population
	if (ctrl == capid->capi_algo_combobox && event == EVENT_REFRESH)
	{
		dlg_update_start(ctrl, dlg);
		dlg_listbox_clear(ctrl, dlg);
		for (int iIndex = 0; iIndex < _countof(szAlgTable); iIndex++)
			dlg_listbox_add(ctrl, dlg, szAlgTable[iIndex]);
		dlg_listbox_select(ctrl, dlg, 1);
		dlg_update_done(ctrl, dlg);
	}

	// handle capi key create button press
	if (ctrl == capid->capi_create_key_button && event == EVENT_ACTION)
	{
        // fetch options for provider type
        int bHardwareToken = (dlg_radiobutton_get(capid->capi_provider_radio, dlg) == 0);

		// special alert about unusual types
		const char* szAlgId = szAlgTable[dlg_listbox_index(capid->capi_algo_combobox, dlg)];
		if (bHardwareToken && (strcmp(szAlgId, "rsa-4096") == 0 || strcmp(szAlgId, "ecdsa-sha2-nistp521") == 0) &&
			MessageBoxW(NULL, L"PuTTY CAC支持所选算法，但许多安全令牌不支持。" \
				L"因此，密钥创建可能会失败。是否要继续？？",
				L"CAPI密钥类型警告", MB_SYSTEMMODAL | MB_ICONQUESTION | MB_YESNO) != IDYES) return;

		char* szSubjectName = dlg_editbox_get(capid->capi_name_text, dlg);
		if (strlen(szSubjectName) == 0)
		{
			MessageBoxW(NULL, L"必须为证书指定使用者名称！！",
				L"无使用者名称", MB_SYSTEMMODAL | MB_ICONERROR | MB_OK);
			sfree(szSubjectName);
			return;
		}

        // attempt to create certificate
        char* szCert = cert_capi_create_key(szAlgId, szSubjectName, bHardwareToken);
        if (szCert != NULL)
        {
            if (MessageBoxW(NULL, L"已成功创建证书。" \
                L"是否要将新证书分配给当前会话？？",
                L"CAPI证书创建成功", MB_SYSTEMMODAL | MB_ICONQUESTION | MB_YESNO) == IDYES)
            {
                conf_set_str(conf, CONF_cert_fingerprint, szCert);
                conf_set_bool(conf, CONF_cert_attempt_auth, 1);                   
            }
            sfree(szCert);
        }
        else
        {
            MessageBoxW(NULL, L"PuTTY无法创建证书。" \
                L"对于硬件令牌，请验证是否连接了兼容令牌。" \
                L"您也可能错误地输入了PIN，" \
                L"或者令牌可能不支持所选算法。",
                L"CAPI证书创建失败", MB_SYSTEMMODAL | MB_ICONERROR | MB_OK);
        }

		sfree(szSubjectName);
	}

	// handle capi key delete button press
	if (ctrl == capid->capi_delete_key_button && event == EVENT_ACTION)
	{
		char* szCert = cert_prompt(IDEN_CAPI, FALSE,
			L"选择要删除的CAPI密钥。如果此密钥位于智能卡或令牌上，" \
			L"PuTTY也将尝试从那里删除它。");
		if (szCert == NULL) return;

		cert_capi_delete_key(szCert);
		sfree(szCert);
	}

	// handle oepn certificate store button press
	if (ctrl == capid->cert_store_button && event == EVENT_ACTION)
	{
		ShellExecuteW(NULL, L"open", L"certmgr.msc", NULL, NULL, SW_SHOWNORMAL);
	}

	// handle default radio bottom selection
	if (ctrl == capid->capi_provider_radio && event == EVENT_REFRESH)
	{
		dlg_radiobutton_set(ctrl, dlg, 0);
	}
}
#endif // PUTTY_CAC

static void sessionsaver_data_free(void *ssdv)
{
    struct sessionsaver_data *ssd = (struct sessionsaver_data *)ssdv;
    get_sesslist(&ssd->sesslist, false);
    sfree(ssd->savedsession);
    sfree(ssd);
}

/*
 * Helper function to load the session selected in the list box, if
 * any, as this is done in more than one place below. Returns 0 for
 * failure.
 */
static bool load_selected_session(
    struct sessionsaver_data *ssd,
    dlgparam *dlg, Conf *conf, bool *maybe_launch)
{
    int i = dlg_listbox_index(ssd->listbox, dlg);
    bool isdef;
    if (i < 0) {
        dlg_beep(dlg);
        return false;
    }
    isdef = !strcmp(ssd->sesslist.sessions[i], "默认设置");
    load_settings(ssd->sesslist.sessions[i], conf);
    sfree(ssd->savedsession);
    ssd->savedsession = dupstr(isdef ? "" : ssd->sesslist.sessions[i]);
    if (maybe_launch)
        *maybe_launch = !isdef;
    dlg_refresh(NULL, dlg);
    /* Restore the selection, which might have been clobbered by
     * changing the value of the edit box. */
    dlg_listbox_select(ssd->listbox, dlg, i);
    return true;
}

static void sessionsaver_handler(dlgcontrol *ctrl, dlgparam *dlg,
                                 void *data, int event)
{
    Conf *conf = (Conf *)data;
    struct sessionsaver_data *ssd =
        (struct sessionsaver_data *)ctrl->context.p;

    if (event == EVENT_REFRESH) {
        if (ctrl == ssd->editbox) {
            dlg_editbox_set(ctrl, dlg, ssd->savedsession);
        } else if (ctrl == ssd->listbox) {
            int i;
            dlg_update_start(ctrl, dlg);
            dlg_listbox_clear(ctrl, dlg);
            for (i = 0; i < ssd->sesslist.nsessions; i++)
                dlg_listbox_add(ctrl, dlg, ssd->sesslist.sessions[i]);
            dlg_update_done(ctrl, dlg);
        }
    } else if (event == EVENT_VALCHANGE) {
        int top, bottom, halfway, i;
        if (ctrl == ssd->editbox) {
            sfree(ssd->savedsession);
            ssd->savedsession = dlg_editbox_get(ctrl, dlg);
            top = ssd->sesslist.nsessions;
            bottom = -1;
            while (top-bottom > 1) {
                halfway = (top+bottom)/2;
                i = strcmp(ssd->savedsession, ssd->sesslist.sessions[halfway]);
                if (i <= 0 ) {
                    top = halfway;
                } else {
                    bottom = halfway;
                }
            }
            if (top == ssd->sesslist.nsessions) {
                top -= 1;
            }
            dlg_listbox_select(ssd->listbox, dlg, top);
        }
    } else if (event == EVENT_ACTION) {
        bool mbl = false;
        if (!ssd->midsession &&
            (ctrl == ssd->listbox ||
             (ssd->loadbutton && ctrl == ssd->loadbutton))) {
            /*
             * The user has double-clicked a session, or hit Load.
             * We must load the selected session, and then
             * terminate the configuration dialog _if_ there was a
             * double-click on the list box _and_ that session
             * contains a hostname.
             */
            if (load_selected_session(ssd, dlg, conf, &mbl) &&
                (mbl && ctrl == ssd->listbox && conf_launchable(conf))) {
                dlg_end(dlg, 1);       /* it's all over, and succeeded */
            }
        } else if (ctrl == ssd->savebutton) {
            bool isdef = !strcmp(ssd->savedsession, "默认设置");
            if (!ssd->savedsession[0]) {
                int i = dlg_listbox_index(ssd->listbox, dlg);
                if (i < 0) {
                    dlg_beep(dlg);
                    return;
                }
                isdef = !strcmp(ssd->sesslist.sessions[i], "默认设置");
                sfree(ssd->savedsession);
                ssd->savedsession = dupstr(isdef ? "" :
                                           ssd->sesslist.sessions[i]);
            }
            {
                char *errmsg = save_settings(ssd->savedsession, conf);
                if (errmsg) {
                    dlg_error_msg(dlg, errmsg);
                    sfree(errmsg);
                }
            }
            get_sesslist(&ssd->sesslist, false);
            get_sesslist(&ssd->sesslist, true);
            dlg_refresh(ssd->editbox, dlg);
            dlg_refresh(ssd->listbox, dlg);
        } else if (!ssd->midsession &&
                   ssd->delbutton && ctrl == ssd->delbutton) {
            int i = dlg_listbox_index(ssd->listbox, dlg);
            if (i <= 0) {
                dlg_beep(dlg);
            } else {
                del_settings(ssd->sesslist.sessions[i]);
                get_sesslist(&ssd->sesslist, false);
                get_sesslist(&ssd->sesslist, true);
                dlg_refresh(ssd->listbox, dlg);
            }
        } else if (ctrl == ssd->okbutton) {
            if (ssd->midsession) {
                /* In a mid-session Change Settings, Apply is always OK. */
                dlg_end(dlg, 1);
                return;
            }
            /*
             * Annoying special case. If the `Open' button is
             * pressed while no host name is currently set, _and_
             * the session list previously had the focus, _and_
             * there was a session selected in that which had a
             * valid host name in it, then load it and go.
             */
            if (dlg_last_focused(ctrl, dlg) == ssd->listbox &&
                !conf_launchable(conf) && dlg_is_visible(ssd->listbox, dlg)) {
                Conf *conf2 = conf_new();
                bool mbl = false;
                if (!load_selected_session(ssd, dlg, conf2, &mbl)) {
                    dlg_beep(dlg);
                    conf_free(conf2);
                    return;
                }
                /* If at this point we have a valid session, go! */
                if (mbl && conf_launchable(conf2)) {
                    conf_copy_into(conf, conf2);
                    dlg_end(dlg, 1);
                } else
                    dlg_beep(dlg);

                conf_free(conf2);
                return;
            }

            /*
             * Otherwise, do the normal thing: if we have a valid
             * session, get going.
             */
            if (conf_launchable(conf)) {
                dlg_end(dlg, 1);
            } else
                dlg_beep(dlg);
        } else if (ctrl == ssd->cancelbutton) {
            dlg_end(dlg, 0);
        }
    }
}

struct charclass_data {
    dlgcontrol *listbox, *editbox, *button;
};

static void charclass_handler(dlgcontrol *ctrl, dlgparam *dlg,
                              void *data, int event)
{
    Conf *conf = (Conf *)data;
    struct charclass_data *ccd =
        (struct charclass_data *)ctrl->context.p;

    if (event == EVENT_REFRESH) {
        if (ctrl == ccd->listbox) {
            int i;
            dlg_update_start(ctrl, dlg);
            dlg_listbox_clear(ctrl, dlg);
            for (i = 0; i < 128; i++) {
                char str[100];
                sprintf(str, "%d\t(0x%02X)\t%c\t%d", i, i,
                        (i >= 0x21 && i != 0x7F) ? i : ' ',
                        conf_get_int_int(conf, CONF_wordness, i));
                dlg_listbox_add(ctrl, dlg, str);
            }
            dlg_update_done(ctrl, dlg);
        }
    } else if (event == EVENT_ACTION) {
        if (ctrl == ccd->button) {
            char *str;
            int i, n;
            str = dlg_editbox_get(ccd->editbox, dlg);
            n = atoi(str);
            sfree(str);
            for (i = 0; i < 128; i++) {
                if (dlg_listbox_issel(ccd->listbox, dlg, i))
                    conf_set_int_int(conf, CONF_wordness, i, n);
            }
            dlg_refresh(ccd->listbox, dlg);
        }
    }
}

struct colour_data {
    dlgcontrol *listbox, *redit, *gedit, *bedit, *button;
};

/* Array of the user-visible colour names defined in the list macro in
 * putty.h */
static const char *const colours[] = {
    #define CONF_COLOUR_NAME_DECL(id,name) name,
    CONF_COLOUR_LIST(CONF_COLOUR_NAME_DECL)
    #undef CONF_COLOUR_NAME_DECL
};

static void colour_handler(dlgcontrol *ctrl, dlgparam *dlg,
                            void *data, int event)
{
    Conf *conf = (Conf *)data;
    struct colour_data *cd =
        (struct colour_data *)ctrl->context.p;
    bool update = false, clear = false;
    int r, g, b;

    if (event == EVENT_REFRESH) {
        if (ctrl == cd->listbox) {
            int i;
            dlg_update_start(ctrl, dlg);
            dlg_listbox_clear(ctrl, dlg);
            for (i = 0; i < lenof(colours); i++)
                dlg_listbox_add(ctrl, dlg, colours[i]);
            dlg_update_done(ctrl, dlg);
            clear = true;
            update = true;
        }
    } else if (event == EVENT_SELCHANGE) {
        if (ctrl == cd->listbox) {
            /* The user has selected a colour. Update the RGB text. */
            int i = dlg_listbox_index(ctrl, dlg);
            if (i < 0) {
                clear = true;
            } else {
                clear = false;
                r = conf_get_int_int(conf, CONF_colours, i*3+0);
                g = conf_get_int_int(conf, CONF_colours, i*3+1);
                b = conf_get_int_int(conf, CONF_colours, i*3+2);
            }
            update = true;
        }
    } else if (event == EVENT_VALCHANGE) {
        if (ctrl == cd->redit || ctrl == cd->gedit || ctrl == cd->bedit) {
            /* The user has changed the colour using the edit boxes. */
            char *str;
            int i, cval;

            str = dlg_editbox_get(ctrl, dlg);
            cval = atoi(str);
            sfree(str);
            if (cval > 255) cval = 255;
            if (cval < 0)   cval = 0;

            i = dlg_listbox_index(cd->listbox, dlg);
            if (i >= 0) {
                if (ctrl == cd->redit)
                    conf_set_int_int(conf, CONF_colours, i*3+0, cval);
                else if (ctrl == cd->gedit)
                    conf_set_int_int(conf, CONF_colours, i*3+1, cval);
                else if (ctrl == cd->bedit)
                    conf_set_int_int(conf, CONF_colours, i*3+2, cval);
            }
        }
    } else if (event == EVENT_ACTION) {
        if (ctrl == cd->button) {
            int i = dlg_listbox_index(cd->listbox, dlg);
            if (i < 0) {
                dlg_beep(dlg);
                return;
            }
            /*
             * Start a colour selector, which will send us an
             * EVENT_CALLBACK when it's finished and allow us to
             * pick up the results.
             */
            dlg_coloursel_start(ctrl, dlg,
                                conf_get_int_int(conf, CONF_colours, i*3+0),
                                conf_get_int_int(conf, CONF_colours, i*3+1),
                                conf_get_int_int(conf, CONF_colours, i*3+2));
        }
    } else if (event == EVENT_CALLBACK) {
        if (ctrl == cd->button) {
            int i = dlg_listbox_index(cd->listbox, dlg);
            /*
             * Collect the results of the colour selector. Will
             * return nonzero on success, or zero if the colour
             * selector did nothing (user hit Cancel, for example).
             */
            if (dlg_coloursel_results(ctrl, dlg, &r, &g, &b)) {
                conf_set_int_int(conf, CONF_colours, i*3+0, r);
                conf_set_int_int(conf, CONF_colours, i*3+1, g);
                conf_set_int_int(conf, CONF_colours, i*3+2, b);
                clear = false;
                update = true;
            }
        }
    }

    if (update) {
        if (clear) {
            dlg_editbox_set(cd->redit, dlg, "");
            dlg_editbox_set(cd->gedit, dlg, "");
            dlg_editbox_set(cd->bedit, dlg, "");
        } else {
            char buf[40];
            sprintf(buf, "%d", r); dlg_editbox_set(cd->redit, dlg, buf);
            sprintf(buf, "%d", g); dlg_editbox_set(cd->gedit, dlg, buf);
            sprintf(buf, "%d", b); dlg_editbox_set(cd->bedit, dlg, buf);
        }
    }
}

struct ttymodes_data {
    dlgcontrol *valradio, *valbox, *setbutton, *listbox;
};

static void ttymodes_handler(dlgcontrol *ctrl, dlgparam *dlg,
                             void *data, int event)
{
    Conf *conf = (Conf *)data;
    struct ttymodes_data *td =
        (struct ttymodes_data *)ctrl->context.p;

    if (event == EVENT_REFRESH) {
        if (ctrl == td->listbox) {
            char *key, *val;
            dlg_update_start(ctrl, dlg);
            dlg_listbox_clear(ctrl, dlg);
            for (val = conf_get_str_strs(conf, CONF_ttymodes, NULL, &key);
                 val != NULL;
                 val = conf_get_str_strs(conf, CONF_ttymodes, key, &key)) {
                char *disp = dupprintf("%s\t%s", key,
                                       (val[0] == 'A') ? "(自动)" :
                                       ((val[0] == 'N') ? "(不发送)"
                                                        : val+1));
                dlg_listbox_add(ctrl, dlg, disp);
                sfree(disp);
            }
            dlg_update_done(ctrl, dlg);
        } else if (ctrl == td->valradio) {
            dlg_radiobutton_set(ctrl, dlg, 0);
        }
    } else if (event == EVENT_SELCHANGE) {
        if (ctrl == td->listbox) {
            int ind = dlg_listbox_index(td->listbox, dlg);
            char *val;
            if (ind < 0) {
                return; /* no item selected */
            }
            val = conf_get_str_str(conf, CONF_ttymodes,
                                   conf_get_str_nthstrkey(conf, CONF_ttymodes,
                                                          ind));
            assert(val != NULL);
            /* Do this first to defuse side-effects on radio buttons: */
            dlg_editbox_set(td->valbox, dlg, val+1);
            dlg_radiobutton_set(td->valradio, dlg,
                                val[0] == 'A' ? 0 : (val[0] == 'N' ? 1 : 2));
        }
    } else if (event == EVENT_VALCHANGE) {
        if (ctrl == td->valbox) {
            /* If they're editing the text box, we assume they want its
             * value to be used. */
            dlg_radiobutton_set(td->valradio, dlg, 2);
        }
    } else if (event == EVENT_ACTION) {
        if (ctrl == td->setbutton) {
            int ind = dlg_listbox_index(td->listbox, dlg);
            const char *key;
            char *str, *val;
            char type;

            {
                const char types[] = {'A', 'N', 'V'};
                int button = dlg_radiobutton_get(td->valradio, dlg);
                assert(button >= 0 && button < lenof(types));
                type = types[button];
            }

            /* Construct new entry */
            if (ind >= 0) {
                key = conf_get_str_nthstrkey(conf, CONF_ttymodes, ind);
                str = (type == 'V' ? dlg_editbox_get(td->valbox, dlg)
                                   : dupstr(""));
                val = dupprintf("%c%s", type, str);
                sfree(str);
                conf_set_str_str(conf, CONF_ttymodes, key, val);
                sfree(val);
                dlg_refresh(td->listbox, dlg);
                dlg_listbox_select(td->listbox, dlg, ind);
            } else {
                /* Not a multisel listbox, so this means nothing selected */
                dlg_beep(dlg);
            }
        }
    }
}

struct environ_data {
    dlgcontrol *varbox, *valbox, *addbutton, *rembutton, *listbox;
};

static void environ_handler(dlgcontrol *ctrl, dlgparam *dlg,
                            void *data, int event)
{
    Conf *conf = (Conf *)data;
    struct environ_data *ed =
        (struct environ_data *)ctrl->context.p;

    if (event == EVENT_REFRESH) {
        if (ctrl == ed->listbox) {
            char *key, *val;
            dlg_update_start(ctrl, dlg);
            dlg_listbox_clear(ctrl, dlg);
            for (val = conf_get_str_strs(conf, CONF_environmt, NULL, &key);
                 val != NULL;
                 val = conf_get_str_strs(conf, CONF_environmt, key, &key)) {
                char *p = dupprintf("%s\t%s", key, val);
                dlg_listbox_add(ctrl, dlg, p);
                sfree(p);
            }
            dlg_update_done(ctrl, dlg);
        }
    } else if (event == EVENT_ACTION) {
        if (ctrl == ed->addbutton) {
            char *key, *val, *str;
            key = dlg_editbox_get(ed->varbox, dlg);
            if (!*key) {
                sfree(key);
                dlg_beep(dlg);
                return;
            }
            val = dlg_editbox_get(ed->valbox, dlg);
            if (!*val) {
                sfree(key);
                sfree(val);
                dlg_beep(dlg);
                return;
            }
            conf_set_str_str(conf, CONF_environmt, key, val);
            str = dupcat(key, "\t", val);
            dlg_editbox_set(ed->varbox, dlg, "");
            dlg_editbox_set(ed->valbox, dlg, "");
            sfree(str);
            sfree(key);
            sfree(val);
            dlg_refresh(ed->listbox, dlg);
        } else if (ctrl == ed->rembutton) {
            int i = dlg_listbox_index(ed->listbox, dlg);
            if (i < 0) {
                dlg_beep(dlg);
            } else {
                char *key, *val;

                key = conf_get_str_nthstrkey(conf, CONF_environmt, i);
                if (key) {
                    /* Populate controls with the entry we're about to delete
                     * for ease of editing */
                    val = conf_get_str_str(conf, CONF_environmt, key);
                    dlg_editbox_set(ed->varbox, dlg, key);
                    dlg_editbox_set(ed->valbox, dlg, val);
                    /* And delete it */
                    conf_del_str_str(conf, CONF_environmt, key);
                }
            }
            dlg_refresh(ed->listbox, dlg);
        }
    }
}

struct portfwd_data {
    dlgcontrol *addbutton, *rembutton, *listbox;
    dlgcontrol *sourcebox, *destbox, *direction;
#ifndef NO_IPV6
    dlgcontrol *addressfamily;
#endif
};

static void portfwd_handler(dlgcontrol *ctrl, dlgparam *dlg,
                            void *data, int event)
{
    Conf *conf = (Conf *)data;
    struct portfwd_data *pfd =
        (struct portfwd_data *)ctrl->context.p;

    if (event == EVENT_REFRESH) {
        if (ctrl == pfd->listbox) {
            char *key, *val;
            dlg_update_start(ctrl, dlg);
            dlg_listbox_clear(ctrl, dlg);
            for (val = conf_get_str_strs(conf, CONF_portfwd, NULL, &key);
                 val != NULL;
                 val = conf_get_str_strs(conf, CONF_portfwd, key, &key)) {
                char *p;
                if (!strcmp(val, "D")) {
                    char *L;
                    /*
                     * A dynamic forwarding is stored as L12345=D or
                     * 6L12345=D (since it's mutually exclusive with
                     * L12345=anything else), but displayed as D12345
                     * to match the fiction that 'Local', 'Remote' and
                     * 'Dynamic' are three distinct modes and also to
                     * align with OpenSSH's command line option syntax
                     * that people will already be used to. So, for
                     * display purposes, find the L in the key string
                     * and turn it into a D.
                     */
                    p = dupprintf("%s\t", key);
                    L = strchr(p, 'L');
                    if (L) *L = 'D';
                } else
                    p = dupprintf("%s\t%s", key, val);
                dlg_listbox_add(ctrl, dlg, p);
                sfree(p);
            }
            dlg_update_done(ctrl, dlg);
        } else if (ctrl == pfd->direction) {
            /*
             * Default is Local.
             */
            dlg_radiobutton_set(ctrl, dlg, 0);
#ifndef NO_IPV6
        } else if (ctrl == pfd->addressfamily) {
            dlg_radiobutton_set(ctrl, dlg, 0);
#endif
        }
    } else if (event == EVENT_ACTION) {
        if (ctrl == pfd->addbutton) {
            const char *family, *type;
            char *src, *key, *val;
            int whichbutton;

#ifndef NO_IPV6
            whichbutton = dlg_radiobutton_get(pfd->addressfamily, dlg);
            if (whichbutton == 1)
                family = "4";
            else if (whichbutton == 2)
                family = "6";
            else
#endif
                family = "";

            whichbutton = dlg_radiobutton_get(pfd->direction, dlg);
            if (whichbutton == 0)
                type = "L";
            else if (whichbutton == 1)
                type = "R";
            else
                type = "D";

            src = dlg_editbox_get(pfd->sourcebox, dlg);
            if (!*src) {
                dlg_error_msg(dlg, "You need to specify a source port number");
                sfree(src);
                return;
            }
            if (*type != 'D') {
                val = dlg_editbox_get(pfd->destbox, dlg);
                if (!*val || !host_strchr(val, ':')) {
                    dlg_error_msg(dlg,
                                  "You need to specify a destination address\n"
                                  "in the form \"host.name:port\"");
                    sfree(src);
                    sfree(val);
                    return;
                }
            } else {
                type = "L";
                val = dupstr("D");     /* special case */
            }

            key = dupcat(family, type, src);
            sfree(src);

            if (conf_get_str_str_opt(conf, CONF_portfwd, key)) {
                dlg_error_msg(dlg, "Specified forwarding already exists");
            } else {
                conf_set_str_str(conf, CONF_portfwd, key, val);
            }

            sfree(key);
            sfree(val);
            dlg_refresh(pfd->listbox, dlg);
        } else if (ctrl == pfd->rembutton) {
            int i = dlg_listbox_index(pfd->listbox, dlg);
            if (i < 0) {
                dlg_beep(dlg);
            } else {
                char *key, *p;
                const char *val;

                key = conf_get_str_nthstrkey(conf, CONF_portfwd, i);
                if (key) {
                    static const char *const afs = "A46";
                    static const char *const dirs = "LRD";
                    const char *afp;
                    int dir;
#ifndef NO_IPV6
                    int idx;
#endif

                    /* Populate controls with the entry we're about to delete
                     * for ease of editing */
                    p = key;

                    afp = strchr(afs, *p);
#ifndef NO_IPV6
                    idx = afp ? afp-afs : 0;
#endif
                    if (afp)
                        p++;
#ifndef NO_IPV6
                    dlg_radiobutton_set(pfd->addressfamily, dlg, idx);
#endif

                    dir = *p;

                    val = conf_get_str_str(conf, CONF_portfwd, key);
                    if (!strcmp(val, "D")) {
                        dir = 'D';
                        val = "";
                    }

                    dlg_radiobutton_set(pfd->direction, dlg,
                                        strchr(dirs, dir) - dirs);
                    p++;

                    dlg_editbox_set(pfd->sourcebox, dlg, p);
                    dlg_editbox_set(pfd->destbox, dlg, val);
                    /* And delete it */
                    conf_del_str_str(conf, CONF_portfwd, key);
                }
            }
            dlg_refresh(pfd->listbox, dlg);
        }
    }
}

struct manual_hostkey_data {
    dlgcontrol *addbutton, *rembutton, *listbox, *keybox;
};

static void manual_hostkey_handler(dlgcontrol *ctrl, dlgparam *dlg,
                                   void *data, int event)
{
    Conf *conf = (Conf *)data;
    struct manual_hostkey_data *mh =
        (struct manual_hostkey_data *)ctrl->context.p;

    if (event == EVENT_REFRESH) {
        if (ctrl == mh->listbox) {
            char *key, *val;
            dlg_update_start(ctrl, dlg);
            dlg_listbox_clear(ctrl, dlg);
            for (val = conf_get_str_strs(conf, CONF_ssh_manual_hostkeys,
                                         NULL, &key);
                 val != NULL;
                 val = conf_get_str_strs(conf, CONF_ssh_manual_hostkeys,
                                         key, &key)) {
                dlg_listbox_add(ctrl, dlg, key);
            }
            dlg_update_done(ctrl, dlg);
        }
    } else if (event == EVENT_ACTION) {
        if (ctrl == mh->addbutton) {
            char *key;

            key = dlg_editbox_get(mh->keybox, dlg);
            if (!*key) {
                dlg_error_msg(dlg, "You need to specify a host key or "
                              "fingerprint");
                sfree(key);
                return;
            }

            if (!validate_manual_hostkey(key)) {
                dlg_error_msg(dlg, "Host key is not in a valid format");
            } else if (conf_get_str_str_opt(conf, CONF_ssh_manual_hostkeys,
                                            key)) {
                dlg_error_msg(dlg, "Specified host key is already listed");
            } else {
                conf_set_str_str(conf, CONF_ssh_manual_hostkeys, key, "");
            }

            sfree(key);
            dlg_refresh(mh->listbox, dlg);
        } else if (ctrl == mh->rembutton) {
            int i = dlg_listbox_index(mh->listbox, dlg);
            if (i < 0) {
                dlg_beep(dlg);
            } else {
                char *key;

                key = conf_get_str_nthstrkey(conf, CONF_ssh_manual_hostkeys, i);
                if (key) {
                    dlg_editbox_set(mh->keybox, dlg, key);
                    /* And delete it */
                    conf_del_str_str(conf, CONF_ssh_manual_hostkeys, key);
                }
            }
            dlg_refresh(mh->listbox, dlg);
        }
    }
}

static void clipboard_selector_handler(dlgcontrol *ctrl, dlgparam *dlg,
                                       void *data, int event)
{
    Conf *conf = (Conf *)data;
    int setting = ctrl->context.i;
#ifdef NAMED_CLIPBOARDS
    int strsetting = ctrl->context2.i;
#endif

    static const struct {
        const char *name;
        int id;
    } options[] = {
        {"无动作", CLIPUI_NONE},
        {CLIPNAME_IMPLICIT, CLIPUI_IMPLICIT},
        {CLIPNAME_EXPLICIT, CLIPUI_EXPLICIT},
    };

    if (event == EVENT_REFRESH) {
        int i, val = conf_get_int(conf, setting);

        dlg_update_start(ctrl, dlg);
        dlg_listbox_clear(ctrl, dlg);

#ifdef NAMED_CLIPBOARDS
        for (i = 0; i < lenof(options); i++)
            dlg_listbox_add(ctrl, dlg, options[i].name);
        if (val == CLIPUI_CUSTOM) {
            const char *sval = conf_get_str(conf, strsetting);
            for (i = 0; i < lenof(options); i++)
                if (!strcmp(sval, options[i].name))
                    break;             /* needs escaping */
            if (i < lenof(options) || sval[0] == '=') {
                char *escaped = dupcat("=", sval);
                dlg_editbox_set(ctrl, dlg, escaped);
                sfree(escaped);
            } else {
                dlg_editbox_set(ctrl, dlg, sval);
            }
        } else {
            dlg_editbox_set(ctrl, dlg, options[0].name); /* fallback */
            for (i = 0; i < lenof(options); i++)
                if (val == options[i].id)
                    dlg_editbox_set(ctrl, dlg, options[i].name);
        }
#else
        for (i = 0; i < lenof(options); i++)
            dlg_listbox_addwithid(ctrl, dlg, options[i].name, options[i].id);
        dlg_listbox_select(ctrl, dlg, 0); /* fallback */
        for (i = 0; i < lenof(options); i++)
            if (val == options[i].id)
                dlg_listbox_select(ctrl, dlg, i);
#endif
        dlg_update_done(ctrl, dlg);
    } else if (event == EVENT_SELCHANGE
#ifdef NAMED_CLIPBOARDS
               || event == EVENT_VALCHANGE
#endif
        ) {
#ifdef NAMED_CLIPBOARDS
        char *sval = dlg_editbox_get(ctrl, dlg);
        int i;

        for (i = 0; i < lenof(options); i++)
            if (!strcmp(sval, options[i].name)) {
                conf_set_int(conf, setting, options[i].id);
                conf_set_str(conf, strsetting, "");
                break;
            }
        if (i == lenof(options)) {
            conf_set_int(conf, setting, CLIPUI_CUSTOM);
            if (sval[0] == '=')
                sval++;
            conf_set_str(conf, strsetting, sval);
        }

        sfree(sval);
#else
        int index = dlg_listbox_index(ctrl, dlg);
        if (index >= 0) {
            int val = dlg_listbox_getid(ctrl, dlg, index);
            conf_set_int(conf, setting, val);
        }
#endif
    }
}

static void clipboard_control(struct controlset *s, const char *label,
                              char shortcut, int percentage, HelpCtx helpctx,
                              int setting, int strsetting)
{
#ifdef NAMED_CLIPBOARDS
    ctrl_combobox(s, label, shortcut, percentage, helpctx,
                  clipboard_selector_handler, I(setting), I(strsetting));
#else
    /* strsetting isn't needed in this case */
    ctrl_droplist(s, label, shortcut, percentage, helpctx,
                  clipboard_selector_handler, I(setting));
#endif
}

static void serial_parity_handler(dlgcontrol *ctrl, dlgparam *dlg,
                                  void *data, int event)
{
    static const struct {
        const char *name;
        int val;
    } parities[] = {
        {"暂无", SER_PAR_NONE},
        {"Odd", SER_PAR_ODD},
        {"Even", SER_PAR_EVEN},
        {"Mark", SER_PAR_MARK},
        {"Space", SER_PAR_SPACE},
    };
    int mask = ctrl->context.i;
    int i, j;
    Conf *conf = (Conf *)data;

    if (event == EVENT_REFRESH) {
        /* Fetching this once at the start of the function ensures we
         * remember what the right value is supposed to be when
         * operations below cause reentrant calls to this function. */
        int oldparity = conf_get_int(conf, CONF_serparity);

        dlg_update_start(ctrl, dlg);
        dlg_listbox_clear(ctrl, dlg);
        for (i = 0; i < lenof(parities); i++)  {
            if (mask & (1 << parities[i].val))
                dlg_listbox_addwithid(ctrl, dlg, parities[i].name,
                                      parities[i].val);
        }
        for (i = j = 0; i < lenof(parities); i++) {
            if (mask & (1 << parities[i].val)) {
                if (oldparity == parities[i].val) {
                    dlg_listbox_select(ctrl, dlg, j);
                    break;
                }
                j++;
            }
        }
        if (i == lenof(parities)) {    /* an unsupported setting was chosen */
            dlg_listbox_select(ctrl, dlg, 0);
            oldparity = SER_PAR_NONE;
        }
        dlg_update_done(ctrl, dlg);
        conf_set_int(conf, CONF_serparity, oldparity);    /* restore */
    } else if (event == EVENT_SELCHANGE) {
        int i = dlg_listbox_index(ctrl, dlg);
        if (i < 0)
            i = SER_PAR_NONE;
        else
            i = dlg_listbox_getid(ctrl, dlg, i);
        conf_set_int(conf, CONF_serparity, i);
    }
}

static void serial_flow_handler(dlgcontrol *ctrl, dlgparam *dlg,
                                void *data, int event)
{
    static const struct {
        const char *name;
        int val;
    } flows[] = {
        {"暂无", SER_FLOW_NONE},
        {"XON/XOFF", SER_FLOW_XONXOFF},
        {"RTS/CTS", SER_FLOW_RTSCTS},
        {"DSR/DTR", SER_FLOW_DSRDTR},
    };
    int mask = ctrl->context.i;
    int i, j;
    Conf *conf = (Conf *)data;

    if (event == EVENT_REFRESH) {
        /* Fetching this once at the start of the function ensures we
         * remember what the right value is supposed to be when
         * operations below cause reentrant calls to this function. */
        int oldflow = conf_get_int(conf, CONF_serflow);

        dlg_update_start(ctrl, dlg);
        dlg_listbox_clear(ctrl, dlg);
        for (i = 0; i < lenof(flows); i++)  {
            if (mask & (1 << flows[i].val))
                dlg_listbox_addwithid(ctrl, dlg, flows[i].name, flows[i].val);
        }
        for (i = j = 0; i < lenof(flows); i++) {
            if (mask & (1 << flows[i].val)) {
                if (oldflow == flows[i].val) {
                    dlg_listbox_select(ctrl, dlg, j);
                    break;
                }
                j++;
            }
        }
        if (i == lenof(flows)) {       /* an unsupported setting was chosen */
            dlg_listbox_select(ctrl, dlg, 0);
            oldflow = SER_FLOW_NONE;
        }
        dlg_update_done(ctrl, dlg);
        conf_set_int(conf, CONF_serflow, oldflow);/* restore */
    } else if (event == EVENT_SELCHANGE) {
        int i = dlg_listbox_index(ctrl, dlg);
        if (i < 0)
            i = SER_FLOW_NONE;
        else
            i = dlg_listbox_getid(ctrl, dlg, i);
        conf_set_int(conf, CONF_serflow, i);
    }
}

void proxy_type_handler(dlgcontrol *ctrl, dlgparam *dlg,
                        void *data, int event)
{
    Conf *conf = (Conf *)data;
    if (event == EVENT_REFRESH) {
        /*
         * We must fetch the previously configured value from the Conf
         * before we start modifying the drop-down list, otherwise the
         * spurious SELCHANGE we trigger in the process will overwrite
         * the value we wanted to keep.
         */
        int proxy_type = conf_get_int(conf, CONF_proxy_type);

        dlg_update_start(ctrl, dlg);
        dlg_listbox_clear(ctrl, dlg);

        int index_to_select = 0, current_index = 0;

#define ADD(id, title) do {                                     \
            dlg_listbox_addwithid(ctrl, dlg, title, id);        \
            if (id == proxy_type)                               \
                index_to_select = current_index;                \
            current_index++;                                    \
        } while (0)

        ADD(PROXY_NONE, "无代理");
        ADD(PROXY_SOCKS5, "SOCKS 5");
        ADD(PROXY_SOCKS4, "SOCKS 4");
        ADD(PROXY_HTTP, "HTTP连接");
        if (ssh_proxy_supported) {
            ADD(PROXY_SSH_TCPIP, "SSH代理 + 端口转发");
            ADD(PROXY_SSH_EXEC, "SSH代理 + 执行命令");
            ADD(PROXY_SSH_SUBSYSTEM, "SSH代理 + 调用子系统");
        }
        if (ctrl->context.i & PROXY_UI_FLAG_LOCAL) {
            ADD(PROXY_CMD, "本地 (运行子程序进行连接)");
        }
        ADD(PROXY_TELNET, "Telnet (临时发送命令)");

#undef ADD

        dlg_listbox_select(ctrl, dlg, index_to_select);

        dlg_update_done(ctrl, dlg);
    } else if (event == EVENT_SELCHANGE) {
        int i = dlg_listbox_index(ctrl, dlg);
        if (i < 0)
            i = AUTO;
        else
            i = dlg_listbox_getid(ctrl, dlg, i);
        conf_set_int(conf, CONF_proxy_type, i);
    }
}

static void host_ca_button_handler(dlgcontrol *ctrl, dlgparam *dp,
                                   void *data, int event)
{
    if (event == EVENT_ACTION)
        show_ca_config_box(dp);
}

void setup_config_box(struct controlbox *b, bool midsession,
                      int protocol, int protcfginfo)
{
    const struct BackendVtable *backvt;
    struct controlset *s;
    struct sessionsaver_data *ssd;
    struct charclass_data *ccd;
    struct colour_data *cd;
    struct ttymodes_data *td;
    struct environ_data *ed;
    struct portfwd_data *pfd;
    struct manual_hostkey_data *mh;
    dlgcontrol *c;
    bool resize_forbidden = false;
    char *str;

    ssd = (struct sessionsaver_data *)
        ctrl_alloc_with_free(b, sizeof(struct sessionsaver_data),
                             sessionsaver_data_free);
    memset(ssd, 0, sizeof(*ssd));
    ssd->savedsession = dupstr("");
    ssd->midsession = midsession;

    /*
     * The standard panel that appears at the bottom of all panels:
     * Open, Cancel, Apply etc.
     */
    s = ctrl_getset(b, "", "", "");
    ctrl_columns(s, 5, 20, 20, 20, 20, 20);
    ssd->okbutton = ctrl_pushbutton(s,
                                    (midsession ? "应用" : "打开"),
                                    (char)(midsession ? 'a' : 'o'),
                                    HELPCTX(no_help),
                                    sessionsaver_handler, P(ssd));
    ssd->okbutton->button.isdefault = true;
    ssd->okbutton->column = 3;
    ssd->cancelbutton = ctrl_pushbutton(s, "关闭", 'c', HELPCTX(no_help),
                                        sessionsaver_handler, P(ssd));
    ssd->cancelbutton->button.iscancel = true;
    ssd->cancelbutton->column = 4;
    /* We carefully don't close the 5-column part, so that platform-
     * specific add-ons can put extra buttons alongside Open and Cancel. */

    /*
     * The Session panel.
     */
    str = dupprintf("%s 基本设置", appname);
    ctrl_settitle(b, "会话", str);
    sfree(str);

    if (!midsession) {
        struct hostport *hp = (struct hostport *)
            ctrl_alloc(b, sizeof(struct hostport));
        memset(hp, 0, sizeof(*hp));

        s = ctrl_getset(b, "会话", "hostport",
                        "指定要连接的目的地址：");
        ctrl_columns(s, 2, 75, 25);
        c = ctrl_editbox(s, HOST_BOX_TITLE, 'n', 100,
                         HELPCTX(session_hostname),
                         config_host_handler, I(0), I(0));
        c->column = 0;
        hp->host = c;
        c = ctrl_editbox(s, PORT_BOX_TITLE, 'p', 100,
                         HELPCTX(session_hostname),
                         config_port_handler, I(0), I(0));
        c->column = 1;
        hp->port = c;

        ctrl_columns(s, 1, 100);
        c = ctrl_text(s, "连接类型：", HELPCTX(session_hostname));
        ctrl_columns(s, 2, 62, 38);
        c = ctrl_radiobuttons(s, NULL, NO_SHORTCUT, 3,
                              HELPCTX(session_hostname),
                              config_protocols_handler, P(hp));
        c->column = 0;
        hp->protradio = c;
        c->radio.buttons = sresize(c->radio.buttons, PROTOCOL_LIMIT, char *);
        c->radio.shortcuts = sresize(c->radio.shortcuts, PROTOCOL_LIMIT, char);
        c->radio.buttondata = sresize(c->radio.buttondata, PROTOCOL_LIMIT,
                                      intorptr);
        assert(c->radio.nbuttons == 0);
        /* UI design assumes there exists at least one 'real' radio button */
        assert(n_ui_backends > 0 && n_ui_backends < PROTOCOL_LIMIT);
        for (size_t i = 0; i < n_ui_backends; i++) {
            assert(backends[i]);
            c->radio.buttons[c->radio.nbuttons] =
                dupstr(backends[i]->displayname_tc);
            c->radio.shortcuts[c->radio.nbuttons] =
                (backends[i]->protocol == PROT_SSH ? 's' :
                 backends[i]->protocol == PROT_SERIAL ? 'r' :
                 backends[i]->protocol == PROT_RAW ? 'w' :  /* FIXME unused */
                 NO_SHORTCUT);
            c->radio.buttondata[c->radio.nbuttons] =
                I(backends[i]->protocol);
            c->radio.nbuttons++;
        }
        /* UI design assumes there exists at least one droplist entry */
        assert(backends[c->radio.nbuttons]);

        c->radio.buttons[c->radio.nbuttons] = dupstr("其它");
        c->radio.shortcuts[c->radio.nbuttons] = 't';
        c->radio.buttondata[c->radio.nbuttons] = I(-1);
        c->radio.nbuttons++;

        c = ctrl_droplist(s, NULL, NO_SHORTCUT, 100,
                          HELPCTX(session_hostname),
                          config_protocols_handler, P(hp));
        hp->protlist = c;
        /* droplist is populated in config_protocols_handler */
        c->column = 1;

        /* Vertically centre the two protocol controls w.r.t. each other */
        hp->protlist->align_next_to = hp->protradio;

        ctrl_columns(s, 1, 100);
    }

    /*
     * The Load/Save panel is available even in mid-session.
     */
    s = ctrl_getset(b, "会话", "savedsessions",
                    midsession ? "---保存当前会话设置---" :
                    "---加载/保存或者删除存储的会话---");
    ctrl_columns(s, 2, 75, 25);
    get_sesslist(&ssd->sesslist, true);
    ssd->editbox = ctrl_editbox(s, "保存会话：", 'e', 100,
                                HELPCTX(session_saved),
                                sessionsaver_handler, P(ssd), P(NULL));
    ssd->editbox->column = 0;
    /* Reset columns so that the buttons are alongside the list, rather
     * than alongside that edit box. */
    ctrl_columns(s, 1, 100);
    ctrl_columns(s, 2, 75, 25);
    ssd->listbox = ctrl_listbox(s, NULL, NO_SHORTCUT,
                                HELPCTX(session_saved),
                                sessionsaver_handler, P(ssd));
    ssd->listbox->column = 0;
    ssd->listbox->listbox.height = 7;
    if (!midsession) {
        ssd->loadbutton = ctrl_pushbutton(s, "加载(L)", 'l',
                                          HELPCTX(session_saved),
                                          sessionsaver_handler, P(ssd));
        ssd->loadbutton->column = 1;
    } else {
        /* We can't offer the Load button mid-session, as it would allow the
         * user to load and subsequently save settings they can't see. (And
         * also change otherwise immutable settings underfoot; that probably
         * shouldn't be a problem, but.) */
        ssd->loadbutton = NULL;
    }
    /* "Save" button is permitted mid-session. */
    ssd->savebutton = ctrl_pushbutton(s, "保存(V)", 'v',
                                      HELPCTX(session_saved),
                                      sessionsaver_handler, P(ssd));
    ssd->savebutton->column = 1;
    if (!midsession) {
        ssd->delbutton = ctrl_pushbutton(s, "删除(D)", 'd',
                                         HELPCTX(session_saved),
                                         sessionsaver_handler, P(ssd));
        ssd->delbutton->column = 1;
    } else {
        /* Disable the Delete button mid-session too, for UI consistency. */
        ssd->delbutton = NULL;
    }
    ctrl_columns(s, 1, 100);

    s = ctrl_getset(b, "会话", "otheropts", NULL);
    ctrl_radiobuttons(s, "退出时关闭窗口：", 'x', 4,
                      HELPCTX(session_coe),
                      conf_radiobutton_handler,
                      I(CONF_close_on_exit),
                      "总是", I(FORCE_ON),
                      "从不", I(FORCE_OFF),
                      "仅正常退出", I(AUTO));

    /*
     * The Session/Logging panel.
     */
    ctrl_settitle(b, "会话/日志", "会话日志设置");

    s = ctrl_getset(b, "会话/日志", "main", NULL);
    /*
     * The logging buttons change depending on whether SSH packet
     * logging can sensibly be available.
     */
    {
        const char *sshlogname, *sshrawlogname;
        if ((midsession && protocol == PROT_SSH) ||
            (!midsession && backend_vt_from_proto(PROT_SSH))) {
            sshlogname = "SSH数据包";
            sshrawlogname = "SSH数据包和raw数据";
        } else {
            sshlogname = NULL;         /* this will disable both buttons */
            sshrawlogname = NULL;      /* this will just placate optimisers */
        }
        ctrl_radiobuttons(s, "会话日志：", NO_SHORTCUT, 2,
                          HELPCTX(logging_main),
                          loggingbuttons_handler,
                          I(CONF_logtype),
                          "暂无日志", 't', I(LGTYP_NONE),
                          "可打印的输出", 'p', I(LGTYP_ASCII),
                          "所有会话输出", 'l', I(LGTYP_DEBUG),
                          sshlogname, 's', I(LGTYP_PACKETS),
                          sshrawlogname, 'r', I(LGTYP_SSHRAW));
    }
    ctrl_filesel(s, "日志文件：", 'f',
                 NULL, true, "选择日志文件",
                 HELPCTX(logging_filename),
                 conf_filesel_handler, I(CONF_logfilename));
    ctrl_text(s, "(名称可包含&Y,&M,&D日期,&T时间,&H主机名,&P端"
                 "口号,例如:log-&h-&y&m&d-&t-&p.log)",
              HELPCTX(logging_filename));
    ctrl_radiobuttons(s, "要记录的日志文件已存在时：", 'e', 1,
                      HELPCTX(logging_exists),
                      conf_radiobutton_handler, I(CONF_logxfovr),
                      "总是覆盖", I(LGXF_OVR),
                      "追加到末尾", I(LGXF_APN),
                      "每次询问", I(LGXF_ASK));
    ctrl_checkbox(s, "频繁刷新日志文件", 'u',
                  HELPCTX(logging_flush),
                  conf_checkbox_handler, I(CONF_logflush));
    ctrl_checkbox(s, "包含标题行", 'i',
                  HELPCTX(logging_header),
                  conf_checkbox_handler, I(CONF_logheader));

    if ((midsession && protocol == PROT_SSH) ||
        (!midsession && backend_vt_from_proto(PROT_SSH))) {
        s = ctrl_getset(b, "会话/日志", "ssh",
                        "特定SSH数据包日志选项：");
        ctrl_checkbox(s, "省略已知密码字段", 'k',
                      HELPCTX(logging_ssh_omit_password),
                      conf_checkbox_handler, I(CONF_logomitpass));
        ctrl_checkbox(s, "省略会话数据", 'd',
                      HELPCTX(logging_ssh_omit_data),
                      conf_checkbox_handler, I(CONF_logomitdata));
    }

    /*
     * The Terminal panel.
     */
    ctrl_settitle(b, "终端", "终端仿真设置");

    s = ctrl_getset(b, "终端", "general", "设置各种终端选项：");
    ctrl_checkbox(s, "开启自动换行模式", 'w',
                  HELPCTX(terminal_autowrap),
                  conf_checkbox_handler, I(CONF_wrap_mode));
    ctrl_checkbox(s, "开启DEC原始模式", 'd',
                  HELPCTX(terminal_decom),
                  conf_checkbox_handler, I(CONF_dec_om));
    ctrl_checkbox(s, "每个LF字符后面增加CR字符", 'r',
                  HELPCTX(terminal_lfhascr),
                  conf_checkbox_handler, I(CONF_lfhascr));
    ctrl_checkbox(s, "每个CR字符后面增加LF字符", 'f',
                  HELPCTX(terminal_crhaslf),
                  conf_checkbox_handler, I(CONF_crhaslf));
    ctrl_checkbox(s, "使用背景颜色清屏", 'e',
                  HELPCTX(terminal_bce),
                  conf_checkbox_handler, I(CONF_bce));
    ctrl_checkbox(s, "启用闪烁文本", 'n',
                  HELPCTX(terminal_blink),
                  conf_checkbox_handler, I(CONF_blinktext));
    ctrl_editbox(s, "回复服务器 ^E 内容查询字符的答复：", 's', 100,
                 HELPCTX(terminal_answerback),
                 conf_editbox_handler, I(CONF_answerback), ED_STR);

    s = ctrl_getset(b, "终端", "ldisc", "行规则选项：");
    ctrl_radiobuttons(s, "本地回显", 'l', 3,
                      HELPCTX(terminal_localecho),
                      conf_radiobutton_handler,I(CONF_localecho),
                      "自动", I(AUTO),
                      "强制开", I(FORCE_ON),
                      "强制关", I(FORCE_OFF));
    ctrl_radiobuttons(s, "本地行编辑", 't', 3,
                      HELPCTX(terminal_localedit),
                      conf_radiobutton_handler,I(CONF_localedit),
                      "自动", I(AUTO),
                      "强制开", I(FORCE_ON),
                      "强制关", I(FORCE_OFF));

    s = ctrl_getset(b, "终端", "printing", "远程打印：");
    ctrl_combobox(s, "发送ANSI码输出到打印机", 'p', 100,
                  HELPCTX(terminal_printing),
                  printerbox_handler, P(NULL), P(NULL));

    /*
     * The Terminal/Keyboard panel.
     */
    ctrl_settitle(b, "终端/键盘",
                  "键盘效果设置");

    s = ctrl_getset(b, "终端/键盘", "mappings",
                    "按键发送效果：");
    ctrl_radiobuttons(s, "Backspace退格键", 'b', 2,
                      HELPCTX(keyboard_backspace),
                      conf_radiobutton_bool_handler,
                      I(CONF_bksp_is_delete),
                      "Control-H", I(0), "Control-? (127)", I(1));
    ctrl_radiobuttons(s, "Home和End键", 'e', 2,
                      HELPCTX(keyboard_homeend),
                      conf_radiobutton_bool_handler,
                      I(CONF_rxvt_homeend),
                      "标准模式", I(false), "rxvt模式", I(true));
    ctrl_radiobuttons(s, "Fun功能键和数字键", 'f', 4,
                      HELPCTX(keyboard_funkeys),
                      conf_radiobutton_handler,
                      I(CONF_funky_type),
                      "ESC[n~", I(FUNKY_TILDE),
                      "Linux", I(FUNKY_LINUX),
                      "Xterm R6", I(FUNKY_XTERM),
                      "VT400", I(FUNKY_VT400),
                      "VT100+", I(FUNKY_VT100P),
                      "SCO", I(FUNKY_SCO),
                      "Xterm 216+", I(FUNKY_XTERM_216));
    ctrl_radiobuttons(s, "Shift/Ctrl/Alt与方向键", 'w', 2,
                      HELPCTX(keyboard_sharrow),
                      conf_radiobutton_handler,
                      I(CONF_sharrow_type),
                      "Ctrl切换模式", I(SHARROW_APPLICATION),
                      "xterm位图风格", I(SHARROW_BITMAP));

    s = ctrl_getset(b, "终端/键盘", "appkeypad",
                    "控制应用程序设置：");
    ctrl_radiobuttons(s, "方向键的初始状态", 'r', 3,
                      HELPCTX(keyboard_appcursor),
                      conf_radiobutton_bool_handler,
                      I(CONF_app_cursor),
                      "常规模式", I(0), "应用模式", I(1));
    ctrl_radiobuttons(s, "数字小键盘的初始状态", 'n', 3,
                      HELPCTX(keyboard_appkeypad),
                      numeric_keypad_handler, P(NULL),
                      "常规模式", I(0), "应用模式", I(1), "NetHack模式", I(2));

    /*
     * The Terminal/Bell panel.
     */
    ctrl_settitle(b, "终端/提示音",
                  "提示音设置");

    s = ctrl_getset(b, "终端/提示音", "style", "设置提示音类型：");
    ctrl_radiobuttons(s, "发出提示音时的动作", 'b', 1,
                      HELPCTX(bell_style),
                      conf_radiobutton_handler, I(CONF_beep),
                      "暂无(禁用提示音)", I(BELL_DISABLED),
                      "系统默认提示音", I(BELL_DEFAULT),
                      "可视提示音(窗口闪烁)", I(BELL_VISUAL));

    s = ctrl_getset(b, "终端/提示音", "overload",
                    "控制提示音重复设置：");
    ctrl_checkbox(s, "过度提醒时暂时禁用提示音", 'd',
                  HELPCTX(bell_overload),
                  conf_checkbox_handler, I(CONF_bellovl));
    ctrl_editbox(s, "判断提示音过度的最少次数", 'm', 20,
                 HELPCTX(bell_overload),
                 conf_editbox_handler, I(CONF_bellovl_n), ED_INT);

    static const struct conf_editbox_handler_type conf_editbox_tickspersec = {
        .type = EDIT_FIXEDPOINT, .denominator = TICKSPERSEC};

    ctrl_editbox(s, "统计提示音过度的间隔秒数", 't', 20,
                 HELPCTX(bell_overload),
                 conf_editbox_handler, I(CONF_bellovl_t),
                 CP(&conf_editbox_tickspersec));
    ctrl_text(s, "提示音禁用一段时间后可以重新启用",
              HELPCTX(bell_overload));
    ctrl_editbox(s, "需要静默的时间是多少秒", 's', 20,
                 HELPCTX(bell_overload),
                 conf_editbox_handler, I(CONF_bellovl_s),
                 CP(&conf_editbox_tickspersec));

    /*
     * The Terminal/Features panel.
     */
    ctrl_settitle(b, "终端/高级设置",
                  "启/禁用高级终端功能");

    s = ctrl_getset(b, "终端/高级设置", "main", NULL);
    ctrl_checkbox(s, "禁用应用程序方向键模式", 'u',
                  HELPCTX(features_application),
                  conf_checkbox_handler, I(CONF_no_applic_c));
    ctrl_checkbox(s, "禁用应用程序数字小键盘模式", 'k',
                  HELPCTX(features_application),
                  conf_checkbox_handler, I(CONF_no_applic_k));
    ctrl_checkbox(s, "禁用xterm风格的鼠标接管", 'x',
                  HELPCTX(features_mouse),
                  conf_checkbox_handler, I(CONF_no_mouse_rep));
    ctrl_checkbox(s, "禁用远程控制调整终端大小", 's',
                  HELPCTX(features_resize),
                  conf_checkbox_handler,
                  I(CONF_no_remote_resize));
    ctrl_checkbox(s, "禁用切换到备用终端屏幕", 'w',
                  HELPCTX(features_altscreen),
                  conf_checkbox_handler, I(CONF_no_alt_screen));
    ctrl_checkbox(s, "禁用远程控制更改窗口标题", 't',
                  HELPCTX(features_retitle),
                  conf_checkbox_handler,
                  I(CONF_no_remote_wintitle));
    ctrl_radiobuttons(s, "对远程标题查询的回应(涉及安全)：", 'q', 3,
                      HELPCTX(features_qtitle),
                      conf_radiobutton_handler,
                      I(CONF_remote_qtitle_action),
                      "无", I(TITLE_NONE),
                      "空字符串", I(TITLE_EMPTY),
                      "窗口标题", I(TITLE_REAL));
    ctrl_checkbox(s, "禁用远程控制清除回滚缓冲区", 'e',
                  HELPCTX(features_clearscroll),
                  conf_checkbox_handler,
                  I(CONF_no_remote_clearscroll));
    ctrl_checkbox(s, "禁用在服务器发送^?时,强制退格删除",'b',
                  HELPCTX(features_dbackspace),
                  conf_checkbox_handler, I(CONF_no_dbackspace));
    ctrl_checkbox(s, "禁用远程控制设置字符集",
                  'r', HELPCTX(features_charset), conf_checkbox_handler,
                  I(CONF_no_remote_charset));
    ctrl_checkbox(s, "禁用阿拉伯语文本修整",
                  'l', HELPCTX(features_arabicshaping), conf_checkbox_handler,
                  I(CONF_no_arabicshaping));
    ctrl_checkbox(s, "禁用双向文本显示",
                  'd', HELPCTX(features_bidi), conf_checkbox_handler,
                  I(CONF_no_bidi));

    /*
     * The Window panel.
     */
    str = dupprintf("%s 窗口设置", appname);
    ctrl_settitle(b, "窗口", str);
    sfree(str);

    backvt = backend_vt_from_proto(protocol);
    if (backvt)
        resize_forbidden = (backvt->flags & BACKEND_RESIZE_FORBIDDEN);

    if (!resize_forbidden || !midsession) {
        s = ctrl_getset(b, "窗口", "size", "设置窗口大小：");
        ctrl_columns(s, 2, 50, 50);
        c = ctrl_editbox(s, "列数", 'm', 100,
                         HELPCTX(window_size),
                         conf_editbox_handler, I(CONF_width), ED_INT);
        c->column = 0;
        c = ctrl_editbox(s, "行数", 'r', 100,
                         HELPCTX(window_size),
                         conf_editbox_handler, I(CONF_height),ED_INT);
        c->column = 1;
        ctrl_columns(s, 1, 100);
    }

    s = ctrl_getset(b, "窗口", "scrollback",
                    "窗口滚动设置：");
    ctrl_editbox(s, "滚动行数", 's', 50,
                 HELPCTX(window_scrollback),
                 conf_editbox_handler, I(CONF_savelines), ED_INT);
    ctrl_checkbox(s, "显示滚动条", 'd',
                  HELPCTX(window_scrollback),
                  conf_checkbox_handler, I(CONF_scrollbar));
    ctrl_checkbox(s, "按键时重置回滚", 'k',
                  HELPCTX(window_scrollback),
                  conf_checkbox_handler, I(CONF_scroll_on_key));
    ctrl_checkbox(s, "显示更新时重置回滚", 'p',
                  HELPCTX(window_scrollback),
                  conf_checkbox_handler, I(CONF_scroll_on_disp));
    ctrl_checkbox(s, "将远程清屏内容推送到回滚", 'e',
                  HELPCTX(window_erased),
                  conf_checkbox_handler,
                  I(CONF_erase_to_scrollback));

    /*
     * The Window/Appearance panel.
     */
    str = dupprintf("%s 窗口外观设置", appname);
    ctrl_settitle(b, "窗口/外观", str);
    sfree(str);

    s = ctrl_getset(b, "窗口/外观", "cursor",
                    "调整光标显示：");
    ctrl_radiobuttons(s, "光标外观", NO_SHORTCUT, 3,
                      HELPCTX(appearance_cursor),
                      conf_radiobutton_handler,
                      I(CONF_cursor_type),
                      "块状", 'l', I(0),
                      "下划线", 'u', I(1),
                      "垂直线", 'v', I(2));
    ctrl_checkbox(s, "光标闪烁", 'b',
                  HELPCTX(appearance_cursor),
                  conf_checkbox_handler, I(CONF_blink_cur));

    s = ctrl_getset(b, "窗口/外观", "font",
                    "字体设置：");
    ctrl_fontsel(s, "终端窗口使用的字体", 'n',
                 HELPCTX(appearance_font),
                 conf_fontsel_handler, I(CONF_font));

    s = ctrl_getset(b, "窗口/外观", "mouse",
                    "鼠标指针调整：");
    ctrl_checkbox(s, "在窗口中输入时隐藏鼠标指针", 'p',
                  HELPCTX(appearance_hidemouse),
                  conf_checkbox_handler, I(CONF_hide_mouseptr));

    s = ctrl_getset(b, "窗口/外观", "border",
                    "调整窗口边框：");
    ctrl_editbox(s, "文本与窗口间的间隙", 'e', 20,
                 HELPCTX(appearance_border),
                 conf_editbox_handler,
                 I(CONF_window_border), ED_INT);

    /*
     * The Window/Behaviour panel.
     */
    str = dupprintf("%s 窗口行为设置", appname);
    ctrl_settitle(b, "窗口/行为", str);
    sfree(str);

    s = ctrl_getset(b, "窗口/行为", "title",
                    "设置窗口标题：");
    ctrl_editbox(s, "窗口标题", 't', 100,
                 HELPCTX(appearance_title),
                 conf_editbox_handler, I(CONF_wintitle), ED_STR);
    ctrl_checkbox(s, "使用单独的标题和图标", 'i',
                  HELPCTX(appearance_title),
                  conf_checkbox_handler,
                  I(CHECKBOX_INVERT | CONF_win_name_always));

    s = ctrl_getset(b, "窗口/行为", "main", NULL);
    ctrl_checkbox(s, "关闭窗口前发出警告", 'w',
                  HELPCTX(behaviour_closewarn),
                  conf_checkbox_handler, I(CONF_warn_on_close));

    /*
     * The Window/Translation panel.
     */
    ctrl_settitle(b, "窗口/字符转换",
                  "字符集转换设置");

    s = ctrl_getset(b, "窗口/字符转换", "trans",
                    "字符集转换：");
    ctrl_combobox(s, "远程字符集",
                  'r', 100, HELPCTX(translation_codepage),
                  codepage_handler, P(NULL), P(NULL));

    s = ctrl_getset(b, "窗口/字符转换", "tweaks", NULL);
    ctrl_checkbox(s, "将模棱两可的字符视为CJK宽字符", 'w',
                  HELPCTX(translation_cjk_ambig_wide),
                  conf_checkbox_handler, I(CONF_cjk_ambig_wide));

    str = dupprintf("调整%s画线字符的处理方式：", appname);
    s = ctrl_getset(b, "窗口/字符转换", "linedraw", str);
    sfree(str);
    ctrl_radiobuttons(
        s, "画线字符处理", NO_SHORTCUT,1,
        HELPCTX(translation_linedraw),
        conf_radiobutton_handler, I(CONF_vtmode),
        "使用Unicode画线代码点绘制",'u',I(VT_UNICODE),
        "简单的画线(+, - and |)",'p',I(VT_POORMAN));
    ctrl_checkbox(s, "将画线字符串复制粘贴为lqqqk",'d',
                  HELPCTX(selection_linedraw),
                  conf_checkbox_handler, I(CONF_rawcnp));
    ctrl_checkbox(s, "即使在UTF-8模式下也启用VT100画线",'8',
                  HELPCTX(translation_utf8linedraw),
                  conf_checkbox_handler, I(CONF_utf8linedraw));

    /*
     * The Window/Selection panel.
     */
    ctrl_settitle(b, "窗口/选择", "复制粘贴设置");

    s = ctrl_getset(b, "窗口/选择", "mouse",
                    "鼠标控制设置：");
    ctrl_checkbox(s, "按Shift键覆盖应用程序对鼠标的使用", 'p',
                  HELPCTX(selection_shiftdrag),
                  conf_checkbox_handler, I(CONF_mouse_override));
    ctrl_radiobuttons(s,
                      "默认的选择模式(按Alt拖动为另外一种)：",
                      NO_SHORTCUT, 2,
                      HELPCTX(selection_rect),
                      conf_radiobutton_bool_handler,
                      I(CONF_rect_select),
                      "常规", 'n', I(false),
                      "矩形框", 'r', I(true));

    s = ctrl_getset(b, "窗口/选择", "clipboards",
                    "复制/粘贴到剪贴板：");
    ctrl_checkbox(s, "所选的文本自动复制到"
                  CLIPNAME_EXPLICIT_OBJECT,
                  NO_SHORTCUT, HELPCTX(selection_autocopy),
                  conf_checkbox_handler, I(CONF_mouseautocopy));
    clipboard_control(s, "鼠标粘贴动作", NO_SHORTCUT, 60,
                      HELPCTX(selection_clipactions),
                      CONF_mousepaste, CONF_mousepaste_custom);
    clipboard_control(s, "{Ctrl,Shift}+Ins", NO_SHORTCUT, 60,
                      HELPCTX(selection_clipactions),
                      CONF_ctrlshiftins, CONF_ctrlshiftins_custom);
    clipboard_control(s, "Ctrl+Shift+{C,V}", NO_SHORTCUT, 60,
                      HELPCTX(selection_clipactions),
                      CONF_ctrlshiftcv, CONF_ctrlshiftcv_custom);

    s = ctrl_getset(b, "窗口/选择", "paste",
                    "将文本从剪贴板粘贴到终端：");
    ctrl_checkbox(s, "允许粘贴文本中的控制字符",
                  NO_SHORTCUT, HELPCTX(selection_pastectrl),
                  conf_checkbox_handler, I(CONF_paste_controls));

    /*
     * The Window/Selection/Copy panel.
     */
    ctrl_settitle(b, "窗口/选择/复制",
                  "从终端复制到剪贴板的设置");

    s = ctrl_getset(b, "窗口/选择/复制", "charclass",
                    "字符间的类别组合：");
    ccd = (struct charclass_data *)
        ctrl_alloc(b, sizeof(struct charclass_data));
    ccd->listbox = ctrl_listbox(s, "字符类定义", 'e',
                                HELPCTX(copy_charclasses),
                                charclass_handler, P(ccd));
    ccd->listbox->listbox.multisel = 1;
    ccd->listbox->listbox.ncols = 4;
    ccd->listbox->listbox.percentages = snewn(4, int);
    ccd->listbox->listbox.percentages[0] = 15;
    ccd->listbox->listbox.percentages[1] = 25;
    ccd->listbox->listbox.percentages[2] = 20;
    ccd->listbox->listbox.percentages[3] = 40;
    ctrl_columns(s, 2, 67, 33);
    ccd->editbox = ctrl_editbox(s, "设置类型", 't', 50,
                                HELPCTX(copy_charclasses),
                                charclass_handler, P(ccd), P(NULL));
    ccd->editbox->column = 0;
    ccd->button = ctrl_pushbutton(s, "设置", 's',
                                  HELPCTX(copy_charclasses),
                                  charclass_handler, P(ccd));
    ccd->button->column = 1;
    ctrl_columns(s, 1, 100);

    /*
     * The Window/Colours panel.
     */
    ctrl_settitle(b, "窗口/颜色", "颜色设置");

    s = ctrl_getset(b, "窗口/颜色", "general",
                    "颜色常规设置：");
    ctrl_checkbox(s, "允许终端指定ANSI颜色", 'i',
                  HELPCTX(colours_ansi),
                  conf_checkbox_handler, I(CONF_ansi_colour));
    ctrl_checkbox(s, "允许终端使用xterm 256色模式", '2',
                  HELPCTX(colours_xterm256), conf_checkbox_handler,
                  I(CONF_xterm_256_colour));
    ctrl_checkbox(s, "允许终端使用24位颜色", '4',
                  HELPCTX(colours_truecolour), conf_checkbox_handler,
                  I(CONF_true_colour));
    ctrl_radiobuttons(s, "如何突出加粗的文本：", 'b', 3,
                      HELPCTX(colours_bold),
                      conf_radiobutton_handler, I(CONF_bold_style),
                      "通过字体", I(1),
                      "通过颜色", I(2),
                      "两者", I(3));

    str = dupprintf("自定义%s颜色显示：", appname);
    s = ctrl_getset(b, "窗口/颜色", "adjust", str);
    sfree(str);
    ctrl_text(s, "请从下表中选择想要改变颜色的表项,设置RGB"
                 "值,然后点\"修改\"使其生效",
              HELPCTX(colours_config));
    ctrl_columns(s, 2, 67, 33);
    cd = (struct colour_data *)ctrl_alloc(b, sizeof(struct colour_data));
    cd->listbox = ctrl_listbox(s, "可调整设置的颜色：", 'u',
                               HELPCTX(colours_config), colour_handler, P(cd));
    cd->listbox->column = 0;
    cd->listbox->listbox.height = 7;
    c = ctrl_text(s, "RGB值：", HELPCTX(colours_config));
    c->column = 1;
    cd->redit = ctrl_editbox(s, "-红-", 'r', 50, HELPCTX(colours_config),
                             colour_handler, P(cd), P(NULL));
    cd->redit->column = 1;
    cd->gedit = ctrl_editbox(s, "-绿-", 'n', 50, HELPCTX(colours_config),
                             colour_handler, P(cd), P(NULL));
    cd->gedit->column = 1;
    cd->bedit = ctrl_editbox(s, "-蓝-", 'e', 50, HELPCTX(colours_config),
                             colour_handler, P(cd), P(NULL));
    cd->bedit->column = 1;
    cd->button = ctrl_pushbutton(s, "修改", 'm', HELPCTX(colours_config),
                                 colour_handler, P(cd));
    cd->button->column = 1;
    ctrl_columns(s, 1, 100);

    /*
     * The Connection panel. This doesn't show up if we're in a
     * non-network utility such as pterm. We tell this by being
     * passed a protocol < 0.
     */
    if (protocol >= 0) {
        ctrl_settitle(b, "连接", "连接设置");

        s = ctrl_getset(b, "连接", "keepalive",
                        "发送空数据包保持会话连接：");
        ctrl_editbox(s, "Keepalives的间隔秒数(0表示关闭)", 'k', 20,
                     HELPCTX(connection_keepalive),
                     conf_editbox_handler, I(CONF_ping_interval), ED_INT);

        if (!midsession) {
            s = ctrl_getset(b, "连接", "tcp",
                            "底层TCP连接选项：");
            ctrl_checkbox(s, "禁用 Nagle 算法(TCP_NODELAY选项)",
                          'n', HELPCTX(connection_nodelay),
                          conf_checkbox_handler,
                          I(CONF_tcp_nodelay));
            ctrl_checkbox(s, "启用TCP Keepalives(SO_KEEPALIVE选项)",
                          'p', HELPCTX(connection_tcpkeepalive),
                          conf_checkbox_handler,
                          I(CONF_tcp_keepalives));
#ifndef NO_IPV6
            s = ctrl_getset(b, "连接", "ipversion",
                            "网络协议版本：");
            ctrl_radiobuttons(s, NULL, NO_SHORTCUT, 3,
                              HELPCTX(connection_ipversion),
                              conf_radiobutton_handler,
                              I(CONF_addressfamily),
                              "自动", 'u', I(ADDRTYPE_UNSPEC),
                              "IPv4", '4', I(ADDRTYPE_IPV4),
                              "IPv6", '6', I(ADDRTYPE_IPV6));
#endif

            {
                const char *label = backend_vt_from_proto(PROT_SSH) ?
                    "远程主机的注册名(用于SSH密钥查找)" :
                    "远程主机的注册名";
                s = ctrl_getset(b, "连接", "identity",
                                "远程主机：");
                ctrl_editbox(s, label, 'm', 100,
                             HELPCTX(connection_loghost),
                             conf_editbox_handler, I(CONF_loghost), ED_STR);
            }
        }

        /*
         * A sub-panel Connection/Data, containing options that
         * decide on data to send to the server.
         */
        if (!midsession) {
            ctrl_settitle(b, "连接/数据", "发送到服务器的数据");

            s = ctrl_getset(b, "连接/数据", "login",
                            "登陆的详细信息：");
            ctrl_editbox(s, "自动登陆用户名", 'u', 50,
                         HELPCTX(connection_username),
                         conf_editbox_handler, I(CONF_username), ED_STR);
            {
                /* We assume the local username is sufficiently stable
                 * to include on the dialog box. */
                char *user = get_username();
                char *userlabel = dupprintf("使用当前用户名(%s)",
                                            user ? user : "");
                sfree(user);
                ctrl_radiobuttons(s, "未指定用户名时：", 'n', 4,
                                  HELPCTX(connection_username_from_env),
                                  conf_radiobutton_bool_handler,
                                  I(CONF_username_from_env),
                                  "提示", I(false),
                                  userlabel, I(true));
                sfree(userlabel);
            }

            s = ctrl_getset(b, "连接/数据", "term",
                            "终端的详细资料：");
            ctrl_editbox(s, "终端类型字符串", 't', 50,
                         HELPCTX(connection_termtype),
                         conf_editbox_handler, I(CONF_termtype), ED_STR);
            ctrl_editbox(s, "终端速度", 's', 50,
                         HELPCTX(connection_termspeed),
                         conf_editbox_handler, I(CONF_termspeed), ED_STR);

            s = ctrl_getset(b, "连接/数据", "env",
                            "环境变量：");
            ctrl_columns(s, 2, 80, 20);
            ed = (struct environ_data *)
                ctrl_alloc(b, sizeof(struct environ_data));
            ed->varbox = ctrl_editbox(s, "变量名", 'v', 60,
                                      HELPCTX(telnet_environ),
                                      environ_handler, P(ed), P(NULL));
            ed->varbox->column = 0;
            ed->valbox = ctrl_editbox(s, "取值", 'l', 60,
                                      HELPCTX(telnet_environ),
                                      environ_handler, P(ed), P(NULL));
            ed->valbox->column = 0;
            ed->addbutton = ctrl_pushbutton(s, "添加", 'd',
                                            HELPCTX(telnet_environ),
                                            environ_handler, P(ed));
            ed->addbutton->column = 1;
            ed->rembutton = ctrl_pushbutton(s, "删除", 'r',
                                            HELPCTX(telnet_environ),
                                            environ_handler, P(ed));
            ed->rembutton->column = 1;
            ctrl_columns(s, 1, 100);
            ed->listbox = ctrl_listbox(s, NULL, NO_SHORTCUT,
                                       HELPCTX(telnet_environ),
                                       environ_handler, P(ed));
            ed->listbox->listbox.height = 3;
            ed->listbox->listbox.ncols = 2;
            ed->listbox->listbox.percentages = snewn(2, int);
            ed->listbox->listbox.percentages[0] = 30;
            ed->listbox->listbox.percentages[1] = 70;
        }

    }

    if (!midsession) {
        /*
         * The Connection/Proxy panel.
         */
        ctrl_settitle(b, "连接/代理",
                      "代理设置");

        s = ctrl_getset(b, "连接/代理", "basics", NULL);
        c = ctrl_droplist(s, "代理类型：", 't', 70,
                          HELPCTX(proxy_type), proxy_type_handler, I(0));
        ctrl_columns(s, 2, 80, 20);
        c = ctrl_editbox(s, "代理主机名", 'y', 100,
                         HELPCTX(proxy_main),
                         conf_editbox_handler,
                         I(CONF_proxy_host), ED_STR);
        c->column = 0;
        c = ctrl_editbox(s, "端口", 'p', 100,
                         HELPCTX(proxy_main),
                         conf_editbox_handler,
                         I(CONF_proxy_port),
                         ED_INT);
        c->column = 1;
        ctrl_columns(s, 1, 100);
        ctrl_editbox(s, "排除主机/IP (逗号分隔,*通配符)", 'e', 100,
                     HELPCTX(proxy_exclude),
                     conf_editbox_handler,
                     I(CONF_proxy_exclude_list), ED_STR);
        ctrl_checkbox(s, "对本地地址不使用代理", 'x',
                      HELPCTX(proxy_exclude),
                      conf_checkbox_handler,
                      I(CONF_even_proxy_localhost));
        ctrl_radiobuttons(s, "是否在代理进行DNS解析：", 'd', 3,
                          HELPCTX(proxy_dns),
                          conf_radiobutton_handler,
                          I(CONF_proxy_dns),
                          "否", I(FORCE_OFF),
                          "自动", I(AUTO),
                          "是", I(FORCE_ON));
        ctrl_editbox(s, "用户名：", 'u', 60,
                     HELPCTX(proxy_auth),
                     conf_editbox_handler,
                     I(CONF_proxy_username), ED_STR);
        c = ctrl_editbox(s, "密码：", 'w', 60,
                         HELPCTX(proxy_auth),
                         conf_editbox_handler,
                         I(CONF_proxy_password), ED_STR);
        c->editbox.password = true;
        ctrl_editbox(s, "要发送到代理的命令(对于某些类型)", 'm', 100,
                     HELPCTX(proxy_command),
                     conf_editbox_handler,
                     I(CONF_proxy_telnet_command), ED_STR);

        ctrl_radiobuttons(s, "是否在终端窗口输出"
                          "代理诊断信息：", 'r', 5,
                          HELPCTX(proxy_logging),
                          conf_radiobutton_handler,
                          I(CONF_proxy_log_to_term),
                          "否", I(FORCE_OFF),
                          "是", I(FORCE_ON),
                          "仅在会话开始时", I(AUTO));
    }

    /*
     * Each per-protocol configuration GUI panel is conditionally
     * displayed. We don't display it if this binary doesn't contain a
     * backend for its protocol at all; we don't display it if we're
     * already in mid-session with a different protocol selected; and
     * even if we _do_ have this protocol selected, we don't display
     * the panel if the protocol doesn't permit any mid-session
     * reconfiguration anyway.
     */

#define DISPLAY_RECONFIGURABLE_PROTOCOL(which_proto) \
    (backend_vt_from_proto(which_proto) && \
     (!midsession || protocol == (which_proto)))
#define DISPLAY_NON_RECONFIGURABLE_PROTOCOL(which_proto) \
    (backend_vt_from_proto(which_proto) && !midsession)

    if (DISPLAY_RECONFIGURABLE_PROTOCOL(PROT_SSH) ||
        DISPLAY_RECONFIGURABLE_PROTOCOL(PROT_SSHCONN)) {
        /*
         * The Connection/SSH panel.
         */
        ctrl_settitle(b, "连接/SSH",
                      "SSH 连接设置");

        /* SSH-1 or connection-sharing downstream */
        if (midsession && (protcfginfo == 1 || protcfginfo == -1)) {
            s = ctrl_getset(b, "连接/SSH", "disclaimer", NULL);
            ctrl_text(s, "此界面中的任何内容都不能在会话中重新"
                      "设置；它只是在这里，以便他的子界面可以"
                      "存在而不感到奇怪。", HELPCTX(no_help));
        }

        if (!midsession) {

            s = ctrl_getset(b, "连接/SSH", "data",
                            "发送到服务器的数据：");
            ctrl_editbox(s, "远程命令", 'r', 100,
                         HELPCTX(ssh_command),
                         conf_editbox_handler, I(CONF_remote_cmd), ED_STR);

            s = ctrl_getset(b, "连接/SSH", "protocol", "协议选项：");
            ctrl_checkbox(s, "不启动shell或命令", 'n',
                          HELPCTX(ssh_noshell),
                          conf_checkbox_handler,
                          I(CONF_ssh_no_shell));
        }

        if (!midsession || !(protcfginfo == 1 || protcfginfo == -1)) {
            s = ctrl_getset(b, "连接/SSH", "protocol", "协议选项：");

            ctrl_checkbox(s, "启用压缩", 'e',
                          HELPCTX(ssh_compress),
                          conf_checkbox_handler,
                          I(CONF_compression));
        }

        if (!midsession) {
            s = ctrl_getset(b, "连接/SSH", "sharing", "在PuTTY工具间共享SSH连接：");

            ctrl_checkbox(s, "如果可能,共享SSH连接", 's',
                          HELPCTX(ssh_share),
                          conf_checkbox_handler,
                          I(CONF_ssh_connection_sharing));

            ctrl_text(s, "共享连接中允许的角色：",
                      HELPCTX(ssh_share));
            ctrl_checkbox(s, "上游(连接到真实服务器的)", 'u',
                          HELPCTX(ssh_share),
                          conf_checkbox_handler,
                          I(CONF_ssh_connection_sharing_upstream));
            ctrl_checkbox(s, "下游(连接到上游PuTTY的)", 'd',
                          HELPCTX(ssh_share),
                          conf_checkbox_handler,
                          I(CONF_ssh_connection_sharing_downstream));
        }

        if (!midsession) {
            s = ctrl_getset(b, "连接/SSH", "protocol", "协议选项：");

            ctrl_radiobuttons(s, "SSH协议版本：", NO_SHORTCUT, 2,
                              HELPCTX(ssh_protocol),
                              conf_radiobutton_handler,
                              I(CONF_sshprot),
                              "2", '2', I(3),
                              "1 (不安全)", '1', I(0));
        }

        /*
         * The Connection/SSH/Kex panel. (Owing to repeat key
         * exchange, much of this is meaningful in mid-session _if_
         * we're using SSH-2 and are not a connection-sharing
         * downstream, or haven't decided yet.)
         */
        if (protcfginfo != 1 && protcfginfo != -1) {
            ctrl_settitle(b, "连接/SSH/密钥交换",
                          "SSH 密钥交换设置");

            s = ctrl_getset(b, "连接/SSH/密钥交换", "main",
                            "密钥交换算法设置：");
            c = ctrl_draglist(s, "算法策略选择", 's',
                              HELPCTX(ssh_kexlist),
                              kexlist_handler, P(NULL));
            c->listbox.height = KEX_MAX;
#ifndef NO_GSSAPI
            ctrl_checkbox(s, "尝试GSSAPI密钥交换",
                          'k', HELPCTX(ssh_gssapi),
                          conf_checkbox_handler,
                          I(CONF_try_gssapi_kex));
#endif

            s = ctrl_getset(b, "连接/SSH/密钥交换", "repeat",
                            "密钥重复交换选项：");

            ctrl_editbox(s, "密钥有效性分钟时长(0=无限制)", 't', 20,
                         HELPCTX(ssh_kex_repeat),
                         conf_editbox_handler,
                         I(CONF_ssh_rekey_time),
                         ED_INT);
#ifndef NO_GSSAPI
            ctrl_editbox(s, "GSS检测的间隔分钟(0=不检测)", NO_SHORTCUT, 20,
                         HELPCTX(ssh_kex_repeat),
                         conf_editbox_handler,
                         I(CONF_gssapirekey),
                         ED_INT);
#endif
            ctrl_editbox(s, "经过密钥的数据流量(0=无限制)", 'x', 20,
                         HELPCTX(ssh_kex_repeat),
                         conf_editbox_handler,
                         I(CONF_ssh_rekey_data),
                         ED_STR);
            ctrl_text(s, "(1M使用1MB,1G使用1GB,等)",
                      HELPCTX(ssh_kex_repeat));
        }

        /*
         * The 'Connection/SSH/Host keys' panel.
         */
        if (protcfginfo != 1 && protcfginfo != -1) {
            ctrl_settitle(b, "连接/SSH/主机密钥",
                          "SSH 主机密钥设置");

            s = ctrl_getset(b, "连接/SSH/主机密钥", "main",
                            "主机密钥算法设置：");
            c = ctrl_draglist(s, "算法策略选择", 's',
                              HELPCTX(ssh_hklist),
                              hklist_handler, P(NULL));
            c->listbox.height = 5;

            ctrl_checkbox(s, "首选已知的主机密钥算法",
                          'p', HELPCTX(ssh_hk_known), conf_checkbox_handler,
                          I(CONF_ssh_prefer_known_hostkeys));
        }

        /*
         * Manual host key configuration is irrelevant mid-session,
         * as we enforce that the host key for rekeys is the
         * same as that used at the start of the session.
         */
        if (!midsession) {
            s = ctrl_getset(b, "连接/SSH/主机密钥", "hostkeys",
                            "为此连接手动配置主机密钥：");

            ctrl_columns(s, 2, 75, 25);
            c = ctrl_text(s, "要接受的主机密钥或指纹",
                          HELPCTX(ssh_kex_manual_hostkeys));
            c->column = 0;
            /* You want to select from the list, _then_ hit Remove. So
             * tab order should be that way round. */
            mh = (struct manual_hostkey_data *)
                ctrl_alloc(b,sizeof(struct manual_hostkey_data));
            mh->rembutton = ctrl_pushbutton(s, "清除", 'r',
                                            HELPCTX(ssh_kex_manual_hostkeys),
                                            manual_hostkey_handler, P(mh));
            mh->rembutton->column = 1;
            mh->rembutton->delay_taborder = true;
            mh->listbox = ctrl_listbox(s, NULL, NO_SHORTCUT,
                                       HELPCTX(ssh_kex_manual_hostkeys),
                                       manual_hostkey_handler, P(mh));
            /* This list box can't be very tall, because there's not
             * much room in the pane on Windows at least. This makes
             * it become really unhelpful if a horizontal scrollbar
             * appears, so we suppress that. */
            mh->listbox->listbox.height = 2;
            mh->listbox->listbox.hscroll = false;
            ctrl_tabdelay(s, mh->rembutton);
            mh->keybox = ctrl_editbox(s, "密钥", 'k', 80,
                                      HELPCTX(ssh_kex_manual_hostkeys),
                                      manual_hostkey_handler, P(mh), P(NULL));
            mh->keybox->column = 0;
            mh->addbutton = ctrl_pushbutton(s, "添加密钥", 'y',
                                            HELPCTX(ssh_kex_manual_hostkeys),
                                            manual_hostkey_handler, P(mh));
            mh->addbutton->column = 1;
            ctrl_columns(s, 1, 100);
        }

        /*
         * But there's no reason not to forbid access to the host CA
         * configuration box, which is common across sessions in any
         * case.
         */
        s = ctrl_getset(b, "连接/SSH/主机密钥", "ca",
                        "配置受信任的证书颁发机构：");
        c = ctrl_pushbutton(s, "配置主机CAs", NO_SHORTCUT,
                            HELPCTX(ssh_kex_cert),
                            host_ca_button_handler, I(0));

        if (!midsession || !(protcfginfo == 1 || protcfginfo == -1)) {
            /*
             * The Connection/SSH/Cipher panel.
             */
            ctrl_settitle(b, "连接/SSH/加密",
                          "SSH 加密设置");

            s = ctrl_getset(b, "连接/SSH/加密",
                            "encryption", "加密选项：");
            c = ctrl_draglist(s, "加密策略选择", 's',
                              HELPCTX(ssh_ciphers),
                              cipherlist_handler, P(NULL));
            c->listbox.height = 6;

            ctrl_checkbox(s, "在SSH-2启用传统的Single-DES加密", 'i',
                          HELPCTX(ssh_ciphers),
                          conf_checkbox_handler,
                          I(CONF_ssh2_des_cbc));
        }

        if (!midsession) {
#ifdef PUTTY_CAC
			/*
			 * The Connection/SSH/Certificate panel.
			 */
			ctrl_settitle(b, "连接/SSH/证书",
				"控制证书/密钥身份验证的选项");
			struct cert_data* certd = (struct cert_data*)ctrl_alloc(b, sizeof(struct cert_data));

			// panel and option to enable certificate auth
			s = ctrl_getset(b, "连接/SSH/证书", "methods",
				"身份验证方法：");
			certd->cert_auth_checkbox = ctrl_checkbox(
				s, "尝试证书/密钥身份验证", NO_SHORTCUT,
				HELPCTX(no_help), conf_checkbox_handler, I(CONF_cert_attempt_auth));
			ctrl_text(s, "注意：启用证书/密钥身份验证将覆盖" \
				"PuTTY\"认证\"面板下的任何密钥文件,使用Pageant时" \
				"此设置无效", HELPCTX(no_help));

			// section for certificate selection
			s = ctrl_getset(b, "连接/SSH/证书", "params", "身份验证参数：");
			ctrl_columns(s, 3, 40, 20, 40);

			// buttons to support setting and remove of certificate
			certd->cert_set_capi_button = ctrl_pushbutton(s, "设置CAPI证书...",
				NO_SHORTCUT, HELPCTX(no_help), cert_event_handler, P(certd));
			certd->cert_set_capi_button->column = 0;
			certd->cert_set_pkcs_button = ctrl_pushbutton(s, "设置PKCS证书...",
				NO_SHORTCUT, HELPCTX(no_help), cert_event_handler, P(certd));
			certd->cert_set_pkcs_button->column = 0;
			certd->cert_set_fido_button = ctrl_pushbutton(s, "设置FIDO密钥...",
				NO_SHORTCUT, HELPCTX(no_help), cert_event_handler, P(certd));
			certd->cert_set_fido_button->column = 0;
			certd->cert_clear_button = ctrl_pushbutton(s, "清除选定项",
				NO_SHORTCUT, HELPCTX(no_help), cert_event_handler, P(certd));
			certd->cert_clear_button->column = 2;
			certd->cert_view_button = ctrl_pushbutton(s, "查看选定项",
				NO_SHORTCUT, HELPCTX(no_help), cert_event_handler, P(certd));
			certd->cert_view_button->column = 2;

			// textbox for thumbprint
			ctrl_text(s, " ", HELPCTX(no_help));
			ctrl_text(s, "所选指纹：", HELPCTX(no_help));
			certd->cert_thumbprint_text = ctrl_text(s, "<未选择密钥或证书>", HELPCTX(no_help));

			// button for keystring
			ctrl_text(s, " ", HELPCTX(no_help));
			ctrl_text(s, "授权密钥文件值：", HELPCTX(no_help));
			certd->cert_copy_clipboard_button = ctrl_pushbutton(s, "复制到剪贴板",
				NO_SHORTCUT, HELPCTX(no_help), cert_event_handler, P(certd));
			certd->cert_copy_clipboard_button->column = 0;

			/*
			 * The Connection/SSH/FIDO Tools panel.
			 */
			ctrl_settitle(b, "连接/SSH/证书/FIDO工具",
				"FIDO令牌密钥管理向导");
			struct fido_data* fidod = (struct fido_data*)ctrl_alloc(b, sizeof(struct fido_data));

			// section for fido creation
			s = ctrl_getset(b, "连接/SSH/证书/FIDO工具", "params", "创建参数：");
			ctrl_columns(s, 3, 45, 10, 45);

			fidod->fido_algo_combobox = ctrl_droplist(s, "密钥算法：", 't',
				65, HELPCTX(no_help), fido_event_handler, P(fidod));

            fidod->fido_app_text = ctrl_editbox(s, "应用程序名称：", NO_SHORTCUT, 64,
                HELPCTX(no_help), fido_event_handler, P(fidod), I(0));

			fidod->fido_display_text = ctrl_editbox(s, "显示名称：", NO_SHORTCUT, 64,
				HELPCTX(no_help), fido_event_handler, P(fidod), I(0));

			fidod->fido_resident_radio = ctrl_radiobuttons(s,
				"密钥类型：", 'r', 1, HELPCTX(no_help), fido_event_handler,
				P(fidod), "驻留密钥", I(FORCE_OFF),
				"非驻留密钥", I(FORCE_OFF), NULL);
			fidod->fido_resident_radio->column = 0;

			fidod->fido_verification_radio = ctrl_radiobuttons(
				s, "用户验证：", 'u', 1, HELPCTX(no_help), fido_event_handler,
				P(fidod), "触摸密钥", I(false), "触摸密钥和PIN", I(true), NULL);
			fidod->fido_verification_radio->column = 2;

			fidod->fido_create_key_button = ctrl_pushbutton(s, "创建密钥...",
				NO_SHORTCUT, HELPCTX(no_help), fido_event_handler, P(fidod));
			fidod->fido_create_key_button->column = 2;

			// section for fido imports
			s = ctrl_getset(b, "连接/SSH/证书/FIDO工具", "import_params", "密钥管理：");

			// adjust so we have two columns with a small separation in the middle
			ctrl_columns(s, 3, 45, 10, 45);

			fidod->fido_clear_key_button = ctrl_pushbutton(s, "清除密钥缓存",
				NO_SHORTCUT, HELPCTX(no_help), fido_event_handler, P(fidod));
			fidod->fido_clear_key_button->column = 0;

			fidod->fido_import_key_button = ctrl_pushbutton(s, "导入密钥...",
				NO_SHORTCUT, HELPCTX(no_help), fido_event_handler, P(fidod));
			fidod->fido_import_key_button->column = 2;

            fidod->fido_import_ssh_button = ctrl_pushbutton(s, "导入密钥文件...",
                NO_SHORTCUT, HELPCTX(no_help), fido_event_handler, P(fidod));
            fidod->fido_import_ssh_button->column = 2;

			fidod->fido_delete_key_button = ctrl_pushbutton(s, "删除密钥...",
				NO_SHORTCUT, HELPCTX(no_help), fido_event_handler, P(fidod));
			fidod->fido_delete_key_button->column = 0;

            ctrl_text(s, "注意：“导入密钥”功能需要提升的本地权限才能成功。", HELPCTX(no_help));

			/*
			 * The Connection/SSH/CAPI Tools panel.
			 */
			ctrl_settitle(b, "连接/SSH/证书/CAPI工具",
				"用于管理CAPI证书的向导");
			struct capi_data* capid = (struct capi_data*)ctrl_alloc(b, sizeof(struct cert_data));

			// section for capi creation
			s = ctrl_getset(b, "连接/SSH/证书/CAPI工具", "params", "创建参数：");
            ctrl_text(s, "使用此选项可用于创建自签名证书(有时在业务" \
                "环境中,硬件令牌可能无法写入)", HELPCTX(no_help));
			ctrl_columns(s, 3, 45, 10, 45);

			capid->capi_algo_combobox = ctrl_droplist(s, "密钥算法：", 't',
				65, HELPCTX(no_help), capi_event_handler, P(capid));

			capid->capi_name_text = ctrl_editbox(s, "使用者名称：", NO_SHORTCUT, 64,
				HELPCTX(no_help), capi_event_handler, P(capid), I(0));
			ctrl_text(s, "使用者名称用于在PUTTY CAC对话框" \
				"中标识证书", HELPCTX(no_help));

			capid->capi_provider_radio = ctrl_radiobuttons(s,
				"提供程序的类型：", 'r', 1, HELPCTX(no_help), capi_event_handler,
				P(capid), "智能卡/令牌", I(FORCE_OFF),
				"软件方式", I(FORCE_OFF), NULL);
			capid->capi_provider_radio->column = 0;

			ctrl_text(s, " ", HELPCTX(no_help))->column = 2;
			capid->capi_create_key_button = ctrl_pushbutton(s, "创建密钥...",
				NO_SHORTCUT, HELPCTX(no_help), capi_event_handler, P(capid));
			capid->capi_create_key_button->column = 2;

			// selection for capi filter
			s = ctrl_getset(b, "连接/SSH/证书/CAPI工具", "filter_params", "证书选择筛选器：");
			ctrl_columns(s, 3, 45, 10, 45);

			ctrl_text(s, "使用选项用来筛选PuTTY和Pageant证书" \
				"选择对话框中显示的证书", HELPCTX(no_help));

            if (!cert_trusted_certs_only(CERT_ENFORCED))
            {
                capid->capi_trusted_certs_checkbox = ctrl_checkbox(s, "仅受信任的",
                    NO_SHORTCUT, HELPCTX(no_help), capi_event_handler, P(capid));
                capid->capi_trusted_certs_checkbox->column = 0;
            }

            if (!cert_smartcard_certs_only(CERT_ENFORCED))
            {
                capid->capi_smartcard_only_checkbox = ctrl_checkbox(s, "仅智能卡",
                    NO_SHORTCUT, HELPCTX(no_help), capi_event_handler, P(capid));
                capid->capi_smartcard_only_checkbox->column = 0;
            }

            if (!cert_ignore_expired_certs(CERT_ENFORCED))
            {
                capid->capi_no_expired_checkbox = ctrl_checkbox(s, "未过期的",
                    NO_SHORTCUT, HELPCTX(no_help), capi_event_handler, P(capid));
                capid->capi_no_expired_checkbox->column = 2;
            }

			// selection for other options filter
			s = ctrl_getset(b, "连接/SSH/证书/CAPI工具", "other_params", "其它选项：");
			ctrl_columns(s, 3, 45, 10, 45);

			capid->cert_store_button = ctrl_pushbutton(s, "打开证书管理...",
				NO_SHORTCUT, HELPCTX(no_help), capi_event_handler, P(capid));
			capid->cert_store_button->column = 0;

			capid->capi_delete_key_button = ctrl_pushbutton(s, "删除密钥...",
				NO_SHORTCUT, HELPCTX(no_help), capi_event_handler, P(capid));
			capid->capi_delete_key_button->column = 2;
#endif // PUTTY_CAC
            /*
             * The Connection/SSH/Auth panel.
             */
            ctrl_settitle(b, "连接/SSH/认证",
                          "SSH 身份认证设置");

            s = ctrl_getset(b, "连接/SSH/认证", "main", NULL);
            ctrl_checkbox(s, "显示预设认证标志(仅SSH-2)",
                          'd', HELPCTX(ssh_auth_banner),
                          conf_checkbox_handler,
                          I(CONF_ssh_show_banner));
            ctrl_checkbox(s, "完全绕过身份验证(仅SSH-2)", 'b',
                          HELPCTX(ssh_auth_bypass),
                          conf_checkbox_handler,
                          I(CONF_ssh_no_userauth));
            ctrl_checkbox(s, "仅连接无密码或密钥验证,则断开连接",
                          'n', HELPCTX(ssh_no_trivial_userauth),
                          conf_checkbox_handler,
                          I(CONF_ssh_no_trivial_userauth));

            s = ctrl_getset(b, "连接/SSH/认证", "methods",
                            "身份验证方法：");
            ctrl_checkbox(s, "尝试使用Pageant进行身份验证", 'p',
                          HELPCTX(ssh_auth_pageant),
                          conf_checkbox_handler,
                          I(CONF_tryagent));
            ctrl_checkbox(s, "尝试TIS或CryptoCard认证(SSH-1)", 'm',
                          HELPCTX(ssh_auth_tis),
                          conf_checkbox_handler,
                          I(CONF_try_tis_auth));
            ctrl_checkbox(s, "尝试\"键盘交互式\"认证(SSH-2)",
                          'i', HELPCTX(ssh_auth_ki),
                          conf_checkbox_handler,
                          I(CONF_try_ki_auth));

            s = ctrl_getset(b, "连接/SSH/认证", "aux",
                            "其他与身份验证相关的选项：");
            ctrl_checkbox(s, "允许代理转发", 'f',
                          HELPCTX(ssh_auth_agentfwd),
                          conf_checkbox_handler, I(CONF_agentfwd));
            ctrl_checkbox(s, "允许在SSH-2中尝试更改用户名", NO_SHORTCUT,
                          HELPCTX(ssh_auth_changeuser),
                          conf_checkbox_handler,
                          I(CONF_change_username));

            ctrl_settitle(b, "连接/SSH/认证/凭证",
                          "用于进行身份验证的凭证");

            s = ctrl_getset(b, "连接/SSH/认证/凭证", "publickey",
                            "公钥身份验证：");
            ctrl_filesel(s, "用于身份验证的私钥文件", 'k',
                         FILTER_KEY_FILES, false, "选择私钥文件",
                         HELPCTX(ssh_auth_privkey),
                         conf_filesel_handler, I(CONF_keyfile));
            ctrl_filesel(s, "要与私钥一起使用的证书"
                         "(自选)", 'e',
                         NULL, false, "选择证书文件",
                         HELPCTX(ssh_auth_cert),
                         conf_filesel_handler, I(CONF_detached_cert));

            s = ctrl_getset(b, "连接/SSH/认证/凭证", "plugin",
                            "提供身份验证响应的插件：");
            ctrl_editbox(s, "要运行的插件命令", NO_SHORTCUT, 100,
                         HELPCTX(ssh_auth_plugin),
                         conf_editbox_handler, I(CONF_auth_plugin), ED_STR);
#ifndef NO_GSSAPI
            /*
             * Connection/SSH/Auth/GSSAPI, which sadly won't fit on
             * the main Auth panel.
             */
            ctrl_settitle(b, "连接/SSH/认证/GSSAPI",
                          "GSSAPI 身份认证设置");
            s = ctrl_getset(b, "连接/SSH/认证/GSSAPI", "gssapi", NULL);

            ctrl_checkbox(s, "尝试GSSAPI身份验证(仅SSH-2)",
                          't', HELPCTX(ssh_gssapi),
                          conf_checkbox_handler,
                          I(CONF_try_gssapi_auth));

            ctrl_checkbox(s, "尝试GSSAPI密钥交换(仅SSH-2)",
                          'k', HELPCTX(ssh_gssapi),
                          conf_checkbox_handler,
                          I(CONF_try_gssapi_kex));

            ctrl_checkbox(s, "允许GSSAPI凭证委托", 'l',
                          HELPCTX(ssh_gssapi_delegation),
                          conf_checkbox_handler,
                          I(CONF_gssapifwd));

            /*
             * GSSAPI library selection.
             */
            if (ngsslibs > 1) {
                c = ctrl_draglist(s, "GSSAPI库的优先顺序：",
                                  'p', HELPCTX(ssh_gssapi_libraries),
                                  gsslist_handler, P(NULL));
                c->listbox.height = ngsslibs;

                /*
                 * I currently assume that if more than one GSS
                 * library option is available, then one of them is
                 * 'user-supplied' and so we should present the
                 * following file selector. This is at least half-
                 * reasonable, because if we're using statically
                 * linked GSSAPI then there will only be one option
                 * and no way to load from a user-supplied library,
                 * whereas if we're using dynamic libraries then
                 * there will almost certainly be some default
                 * option in addition to a user-supplied path. If
                 * anyone ever ports PuTTY to a system on which
                 * dynamic-library GSSAPI is available but there is
                 * absolutely no consensus on where to keep the
                 * libraries, there'll need to be a flag alongside
                 * ngsslibs to control whether the file selector is
                 * displayed.
                 */

                ctrl_filesel(s, "用户提供的GSSAPI库路径：", 's',
                             FILTER_DYNLIB_FILES, false, "选择库文件",
                             HELPCTX(ssh_gssapi_libraries),
                             conf_filesel_handler,
                             I(CONF_ssh_gss_custom));
            }
#endif
        }

        if (!midsession) {
            /*
             * The Connection/SSH/TTY panel.
             */
            ctrl_settitle(b, "连接/SSH/TTY", "远程终端设置");

            s = ctrl_getset(b, "连接/SSH/TTY", "sshtty", NULL);
            ctrl_checkbox(s, "不分配伪终端", 'p',
                          HELPCTX(ssh_nopty),
                          conf_checkbox_handler,
                          I(CONF_nopty));

            s = ctrl_getset(b, "连接/SSH/TTY", "ttymodes",
                            "终端模式：");
            td = (struct ttymodes_data *)
                ctrl_alloc(b, sizeof(struct ttymodes_data));
            ctrl_text(s, "发送终端模式", HELPCTX(ssh_ttymodes));
            td->listbox = ctrl_listbox(s, NULL, NO_SHORTCUT,
                                       HELPCTX(ssh_ttymodes),
                                       ttymodes_handler, P(td));
            td->listbox->listbox.height = 8;
            td->listbox->listbox.ncols = 2;
            td->listbox->listbox.percentages = snewn(2, int);
            td->listbox->listbox.percentages[0] = 40;
            td->listbox->listbox.percentages[1] = 60;
            ctrl_columns(s, 2, 75, 25);
            c = ctrl_text(s, "对于选定的模式,发送：", HELPCTX(ssh_ttymodes));
            c->column = 0;
            td->setbutton = ctrl_pushbutton(s, "设置", 's',
                                            HELPCTX(ssh_ttymodes),
                                            ttymodes_handler, P(td));
            td->setbutton->column = 1;
            td->setbutton->delay_taborder = true;
            ctrl_columns(s, 1, 100);        /* column break */
            /* Bit of a hack to get the value radio buttons and
             * edit-box on the same row. */
            ctrl_columns(s, 2, 75, 25);
            td->valradio = ctrl_radiobuttons(s, NULL, NO_SHORTCUT, 3,
                                             HELPCTX(ssh_ttymodes),
                                             ttymodes_handler, P(td),
                                             "自动", NO_SHORTCUT, P(NULL),
                                             "无", NO_SHORTCUT, P(NULL),
                                             "内容：", NO_SHORTCUT, P(NULL));
            td->valradio->column = 0;
            td->valbox = ctrl_editbox(s, NULL, NO_SHORTCUT, 100,
                                      HELPCTX(ssh_ttymodes),
                                      ttymodes_handler, P(td), P(NULL));
            td->valbox->column = 1;
            td->valbox->align_next_to = td->valradio;
            ctrl_tabdelay(s, td->setbutton);
        }

        if (!midsession) {
            /*
             * The Connection/SSH/X11 panel.
             */
            ctrl_settitle(b, "连接/SSH/X11",
                          "SSH X11 转发设置");

            s = ctrl_getset(b, "连接/SSH/X11", "x11", "X11转发：");
            ctrl_checkbox(s, "启用X11转发", 'e',
                          HELPCTX(ssh_tunnels_x11),
                          conf_checkbox_handler,I(CONF_x11_forward));
            ctrl_editbox(s, "X显示位置", 'x', 50,
                         HELPCTX(ssh_tunnels_x11),
                         conf_editbox_handler, I(CONF_x11_display), ED_STR);
            ctrl_radiobuttons(s, "远程X11认证协议：", 'u', 2,
                              HELPCTX(ssh_tunnels_x11auth),
                              conf_radiobutton_handler,
                              I(CONF_x11_auth),
                              "MIT-Magic-Cookie-1", I(X11_MIT),
                              "XDM-Authorization-1", I(X11_XDM));
        }

        /*
         * The Tunnels panel _is_ still available in mid-session.
         */
        ctrl_settitle(b, "连接/SSH/隧道",
                      "SSH 端口转发设置");

        s = ctrl_getset(b, "连接/SSH/隧道", "portfwd",
                        "端口转发：");
        ctrl_checkbox(s, "本地端口接受来自其他主机的连接",'t',
                      HELPCTX(ssh_tunnels_portfwd_localhost),
                      conf_checkbox_handler,
                      I(CONF_lport_acceptall));
        ctrl_checkbox(s, "远程端口也是如此(仅限SSH-2)", 'p',
                      HELPCTX(ssh_tunnels_portfwd_localhost),
                      conf_checkbox_handler,
                      I(CONF_rport_acceptall));

        ctrl_columns(s, 3, 55, 20, 25);
        c = ctrl_text(s, "转发端口：", HELPCTX(ssh_tunnels_portfwd));
        c->column = COLUMN_FIELD(0,2);
        /* You want to select from the list, _then_ hit Remove. So tab order
         * should be that way round. */
        pfd = (struct portfwd_data *)ctrl_alloc(b,sizeof(struct portfwd_data));
        pfd->rembutton = ctrl_pushbutton(s, "删除", 'r',
                                         HELPCTX(ssh_tunnels_portfwd),
                                         portfwd_handler, P(pfd));
        pfd->rembutton->column = 2;
        pfd->rembutton->delay_taborder = true;
        pfd->listbox = ctrl_listbox(s, NULL, NO_SHORTCUT,
                                    HELPCTX(ssh_tunnels_portfwd),
                                    portfwd_handler, P(pfd));
        pfd->listbox->listbox.height = 3;
        pfd->listbox->listbox.ncols = 2;
        pfd->listbox->listbox.percentages = snewn(2, int);
        pfd->listbox->listbox.percentages[0] = 20;
        pfd->listbox->listbox.percentages[1] = 80;
        ctrl_tabdelay(s, pfd->rembutton);
        ctrl_text(s, "添加新的转发端口：", HELPCTX(ssh_tunnels_portfwd));
        /* You want to enter source, destination and type, _then_ hit Add.
         * Again, we adjust the tab order to reflect this. */
        pfd->addbutton = ctrl_pushbutton(s, "添加", 'd',
                                         HELPCTX(ssh_tunnels_portfwd),
                                         portfwd_handler, P(pfd));
        pfd->addbutton->column = 2;
        pfd->addbutton->delay_taborder = true;
        pfd->sourcebox = ctrl_editbox(s, "源端口", 's', 40,
                                      HELPCTX(ssh_tunnels_portfwd),
                                      portfwd_handler, P(pfd), P(NULL));
        pfd->sourcebox->column = 0;
        pfd->destbox = ctrl_editbox(s, "目的地", 'i', 67,
                                    HELPCTX(ssh_tunnels_portfwd),
                                    portfwd_handler, P(pfd), P(NULL));
        pfd->direction = ctrl_radiobuttons(s, NULL, NO_SHORTCUT, 3,
                                           HELPCTX(ssh_tunnels_portfwd),
                                           portfwd_handler, P(pfd),
                                           "本地", 'l', P(NULL),
                                           "远端", 'm', P(NULL),
                                           "动态", 'y', P(NULL));
#ifndef NO_IPV6
        pfd->addressfamily =
            ctrl_radiobuttons(s, NULL, NO_SHORTCUT, 3,
                              HELPCTX(ssh_tunnels_portfwd_ipversion),
                              portfwd_handler, P(pfd),
                              "自动", 'u', I(ADDRTYPE_UNSPEC),
                              "IPv4", '4', I(ADDRTYPE_IPV4),
                              "IPv6", '6', I(ADDRTYPE_IPV6));
#endif
        ctrl_tabdelay(s, pfd->addbutton);
        ctrl_columns(s, 1, 100);

        if (!midsession) {
            /*
             * The Connection/SSH/Bugs panels.
             */
            ctrl_settitle(b, "连接/SSH/纠错",
                          "SSH 服务出错的解决方法");

            s = ctrl_getset(b, "连接/SSH/纠错", "main",
                            "检测SSH服务中已知的错误：");
            ctrl_droplist(s, "阻塞SSH-2的忽略消息", '2', 20,
                          HELPCTX(ssh_bugs_ignore2),
                          sshbug_handler, I(CONF_sshbug_ignore2));
            ctrl_droplist(s, "错误的处理SSH-2密钥重复交换", 'k', 20,
                          HELPCTX(ssh_bugs_rekey2),
                          sshbug_handler, I(CONF_sshbug_rekey2));
            ctrl_droplist(s, "PuTTY的SSH-2'winadj'请求阻塞", 'j',
                          20, HELPCTX(ssh_bugs_winadj),
                          sshbug_handler, I(CONF_sshbug_winadj));
            ctrl_droplist(s, "回复已关闭通道的请求", 'q', 20,
                          HELPCTX(ssh_bugs_chanreq),
                          sshbug_handler, I(CONF_sshbug_chanreq));
            ctrl_droplist(s, "忽略SSH-2最大数据包大小", 'x', 20,
                          HELPCTX(ssh_bugs_maxpkt2),
                          sshbug_handler, I(CONF_sshbug_maxpkt2));

            s = ctrl_getset(b, "连接/SSH/纠错", "manual",
                            "手动启用的解决方法：");
            ctrl_droplist(s, "丢弃服务器SSH问候语之前发送的数据", 'd', 20,
                          HELPCTX(ssh_bugs_dropstart),
                          sshbug_handler_manual_only,
                          I(CONF_sshbug_dropstart));
            ctrl_droplist(s, "阻塞PuTTY上的所有KEXINIT", 'p', 20,
                          HELPCTX(ssh_bugs_filter_kexinit),
                          sshbug_handler_manual_only,
                          I(CONF_sshbug_filter_kexinit));

            ctrl_settitle(b, "连接/SSH/更多纠错",
                          "SSH 服务出错的更多解决方法");

            s = ctrl_getset(b, "连接/SSH/更多纠错", "main",
                            "检测SSH服务已知的错误：");
            ctrl_droplist(s, "旧的RSA/SHA2证书算法命名", 'l', 20,
                          HELPCTX(ssh_bugs_rsa_sha2_cert_userauth),
                          sshbug_handler,
                          I(CONF_sshbug_rsa_sha2_cert_userauth));
            ctrl_droplist(s, "需要对SSH-2 RSA签名进行填充", 'p', 20,
                          HELPCTX(ssh_bugs_rsapad2),
                          sshbug_handler, I(CONF_sshbug_rsapad2));
            ctrl_droplist(s, "仅支持pre-RFC4419 SSH-2 DH GEX", 'd', 20,
                          HELPCTX(ssh_bugs_oldgex2),
                          sshbug_handler, I(CONF_sshbug_oldgex2));
            ctrl_droplist(s, "错误计算SSH-2 HMAC密钥", 'm', 20,
                          HELPCTX(ssh_bugs_hmac2),
                          sshbug_handler, I(CONF_sshbug_hmac2));
            ctrl_droplist(s, "滥用SSH-2 PK身份验证中的会话ID", 'n', 20,
                          HELPCTX(ssh_bugs_pksessid2),
                          sshbug_handler, I(CONF_sshbug_pksessid2));
            ctrl_droplist(s, "错误计算SSH-2加密密钥", 'e', 20,
                          HELPCTX(ssh_bugs_derivekey2),
                          sshbug_handler, I(CONF_sshbug_derivekey2));
            ctrl_droplist(s, "阻塞SSH-1的忽略消息", 'i', 20,
                          HELPCTX(ssh_bugs_ignore1),
                          sshbug_handler, I(CONF_sshbug_ignore1));
            ctrl_droplist(s, "拒绝所有SSH-1密码伪装", 's', 20,
                          HELPCTX(ssh_bugs_plainpw1),
                          sshbug_handler, I(CONF_sshbug_plainpw1));
            ctrl_droplist(s, "阻塞SSH-1 RSA认证", 'r', 20,
                          HELPCTX(ssh_bugs_rsa1),
                          sshbug_handler, I(CONF_sshbug_rsa1));
        }
    }

    if (DISPLAY_RECONFIGURABLE_PROTOCOL(PROT_SERIAL)) {
        const BackendVtable *ser_vt = backend_vt_from_proto(PROT_SERIAL);

        /*
         * The Connection/Serial panel.
         */
        ctrl_settitle(b, "连接/串口",
                      "串口设置");

        if (!midsession) {
            /*
             * We don't permit switching to a different serial port in
             * midflight, although we do allow all other
             * reconfiguration.
             */
            s = ctrl_getset(b, "连接/串口", "serline",
                            "选择串口：");
            ctrl_editbox(s, "要连接的串口", 'l', 40,
                         HELPCTX(serial_line),
                         conf_editbox_handler, I(CONF_serline), ED_STR);
        }

        s = ctrl_getset(b, "连接/串口", "sercfg", "串口配置：");
        ctrl_editbox(s, "速度(波特率)", 's', 40,
                     HELPCTX(serial_speed),
                     conf_editbox_handler, I(CONF_serspeed), ED_INT);
        ctrl_editbox(s, "数据位", 'b', 40,
                     HELPCTX(serial_databits),
                     conf_editbox_handler, I(CONF_serdatabits), ED_INT);
        /*
         * Stop bits come in units of one half.
         */
        static const struct conf_editbox_handler_type conf_editbox_stopbits = {
            .type = EDIT_FIXEDPOINT, .denominator = 2};

        ctrl_editbox(s, "停止位", 't', 40,
                     HELPCTX(serial_stopbits),
                     conf_editbox_handler, I(CONF_serstopbits),
                     CP(&conf_editbox_stopbits));
        ctrl_droplist(s, "奇偶校验", 'p', 40,
                      HELPCTX(serial_parity), serial_parity_handler,
                      I(ser_vt->serial_parity_mask));
        ctrl_droplist(s, "流量控制", 'f', 40,
                      HELPCTX(serial_flow), serial_flow_handler,
                      I(ser_vt->serial_flow_mask));
    }

    if (DISPLAY_RECONFIGURABLE_PROTOCOL(PROT_TELNET)) {
        /*
         * The Connection/Telnet panel.
         */
        ctrl_settitle(b, "连接/Telnet",
                      "Telnet 连接设置");

        s = ctrl_getset(b, "连接/Telnet", "protocol",
                        "Telnet协议调整：");

        if (!midsession) {
            ctrl_radiobuttons(s, "处理OLD_ENVIRON参数歧义",
                              NO_SHORTCUT, 2,
                              HELPCTX(telnet_oldenviron),
                              conf_radiobutton_bool_handler,
                              I(CONF_rfc_environ),
                              "BSD (一般)", 'b', I(false),
                              "RFC 1408 (特殊)", 'f', I(true));
            ctrl_radiobuttons(s, "Telnet通讯模式：", 't', 2,
                              HELPCTX(telnet_passive),
                              conf_radiobutton_bool_handler,
                              I(CONF_passive_telnet),
                              "被动", I(true), "主动", I(false));
        }
        ctrl_checkbox(s, "键盘发送Telnet特殊命令", 'k',
                      HELPCTX(telnet_specialkeys),
                      conf_checkbox_handler,
                      I(CONF_telnet_keyboard));
        ctrl_checkbox(s, "Return回车键发送Telnet新行代码而不是^M",
                      'm', HELPCTX(telnet_newline),
                      conf_checkbox_handler,
                      I(CONF_telnet_newline));
    }

    if (DISPLAY_NON_RECONFIGURABLE_PROTOCOL(PROT_RLOGIN)) {
        /*
         * The Connection/Rlogin panel.
         */
        ctrl_settitle(b, "连接/Rlogin",
                      "Rlogin 连接设置");

        s = ctrl_getset(b, "连接/Rlogin", "data",
                        "发送到服务器的数据：");
        ctrl_editbox(s, "本地用户名", 'l', 50,
                     HELPCTX(rlogin_localuser),
                     conf_editbox_handler, I(CONF_localusername), ED_STR);

    }

    if (DISPLAY_NON_RECONFIGURABLE_PROTOCOL(PROT_SUPDUP)) {
        /*
         * The Connection/SUPDUP panel.
         */
        ctrl_settitle(b, "连接/SUPDUP",
                      "SUPDUP 连接设置");

        s = ctrl_getset(b, "连接/SUPDUP", "main", NULL);

        ctrl_editbox(s, "位置字符串：", 'l', 70,
                     HELPCTX(supdup_location),
                     conf_editbox_handler, I(CONF_supdup_location),
                     ED_STR);

        ctrl_radiobuttons(s, "扩展ASCII字符集：", 'e', 4,
                          HELPCTX(supdup_ascii),
                          conf_radiobutton_handler,
                          I(CONF_supdup_ascii_set),
                          "无", I(SUPDUP_CHARSET_ASCII),
                          "ITS", I(SUPDUP_CHARSET_ITS),
                          "WAITS", I(SUPDUP_CHARSET_WAITS));

        ctrl_checkbox(s, "**MORE** 处理", 'm',
                      HELPCTX(supdup_more),
                      conf_checkbox_handler,
                      I(CONF_supdup_more));

        ctrl_checkbox(s, "终端滚动", 's',
                      HELPCTX(supdup_scroll),
                      conf_checkbox_handler,
                      I(CONF_supdup_scroll));
    }
}
