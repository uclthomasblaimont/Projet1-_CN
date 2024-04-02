from collections import defaultdict


dict =  {'dropbox.com': {'127.0.0.1', '192.168.1.61'}, 'detectportal.firefox.com': {'127.0.0.1'}, 'contile.services.mozilla.com': {'127.0.0.1', '192.168.1.61'}, 'spocs.mozilla.net': {'127.0.0.1', '192.168.1.61'}, 'ocsp.digicert.com': {'127.0.0.1'}, 'fp2e7a.wpc.phicdn.net': {'192.168.1.61'}, 'prod.ads.prod.webservices.mozgcp.net': {'192.168.1.61'}, 'example.org': {'127.0.0.1'}, 'ipv4only.arpa': {'127.0.0.1', '192.168.1.61'}, 'content-signature-2.cdn.mozilla.net': {'127.0.0.1'}, 'r3.o.lencr.org': {'127.0.0.1', '192.168.1.61'}, 'www.dropbox.com': {'127.0.0.1', '192.168.1.61'}, 'push.services.mozilla.com': {'127.0.0.1'}, 'autopush.prod.mozaws.net': {'192.168.1.61'}, 'incoming.telemetry.mozilla.org': {'127.0.0.1'}, 'telemetry-incoming.r53-2.services.mozilla.com': {'192.168.1.61'}, 'firefox.settings.services.mozilla.com': {'127.0.0.1'}, 'prod.remote-settings.prod.webservices.mozgcp.net': {'192.168.1.61'}, 'chat.openai.com': {'127.0.0.1'}, 'moodle.uclouvain.be': {'127.0.0.1'}, 'www.youtube.com': {'127.0.0.1'}, 'outlook.office.com': {'127.0.0.1', '192.168.1.61'}, 'github.com': {'127.0.0.1', '192.168.1.61'}, 'www.dhnet.be': {'127.0.0.1', '192.168.1.61'}, 'www.overleaf.com': {'127.0.0.1'}, 'inginious.info.ucl.ac.be': {'127.0.0.1'}, 'lb2.overleaf.com': {'192.168.1.61'}, 'idp.uclouvain.be': {'127.0.0.1'}, 'www.deepl.com': {'127.0.0.1'}, 'forge.uclouvain.be': {'127.0.0.1'}, 'www.figma.com': {'127.0.0.1', '192.168.1.61'}, 'forge.sgsi.ucl.ac.be': {'192.168.1.61'}, 'www.crunchyroll.com': {'127.0.0.1', '192.168.1.61'}, 'cemantix.certitudes.org': {'127.0.0.1'}, 'www.quick.be': {'127.0.0.1', '192.168.1.61'}, 'www.perplexity.ai': {'127.0.0.1'}, 'cfl.dropboxstatic.com': {'127.0.0.1'}, 'fjord.dropboxstatic.com': {'127.0.0.1', '192.168.1.61'}, 'consent.dropbox.com': {'127.0.0.1', '192.168.1.61'}, 'snapengage.dropbox.com': {'127.0.0.1', '192.168.1.61'}, 'safebrowsing.googleapis.com': {'127.0.0.1', '192.168.1.61'}, 'ocsp.pki.goog': {'127.0.0.1', '192.168.1.61'}, 'accounts.google.com': {'127.0.0.1', '192.168.1.61'}, 'aem.dropbox.com': {'127.0.0.1', '192.168.1.61'}, 'stun.l.google.com': {'127.0.0.1', '192.168.1.61'}, 'stun.fpapi.io': {'127.0.0.1', '192.168.1.61'}, 'stun.fpapi.io.lan': {'127.0.0.1', '192.168.1.61'}, 'www.gstatic.com': {'127.0.0.1', '192.168.1.61'}}

def dropbox_checker(input_dict):
    # Créer un nouveau dictionnaire pour stocker les entrées filtrées
    filtered_dict = dict

    # Itérer sur chaque paire clé-valeur de l'input_dict
    for key, value in input_dict.items():
        # Vérifier si "dropbox" est dans la clé
        if "dropbox" in key:
            # Si oui, ajouter la clé et la valeur au filtered_dict
            filtered_dict[key] = value

    return filtered_dict

print(dropbox_checker(dict))




