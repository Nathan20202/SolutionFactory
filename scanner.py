from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
import re
import shutil
import requests
import time
import tkinter as tk
import ttkbootstrap as ttk
from tkinter import filedialog, messagebox
import json
import os
import hashlib
import threading
from PIL import ImageTk, Image

# Insérez votre clé API VirusTotal ici
VIRUSTOTAL_API_KEY = "3eff0d8e7a84175c8d9d805ea55977fb4ef05019ce6324416fafc989243ec0d2"
METADEFENDER_API_KEY = "16a733e289e6920b07c4b860c0b67181"
HYBRIDANALYSIS_API_KEY = "jvldyri305565a2e3ss2luqkc559cf66vuhiqoldda0ad51fkg5fgurecbee7aa4"

# Votre répertoire d'importance
IMPORTANT_DIR = r'C:\Users\natha\Documents\Dossier_Important'

# Déclaration des variables de sélection des analyseurs
use_check = True
use_virustotal = False
use_metadefender = False
use_hybridanalysis = False


class FileScanner:
    def __init__(self, api_key):
        # Initialisation de l'instance avec la clé API fournie
        self.api_key = api_key
        self.cache_dir = r'C:\Users\natha\Documents\Fichiers_Tri'

    @staticmethod
    def handle_scan_result(ransomware_detected, file_path):
        if ransomware_detected:
            # Si un ransomware est détecté
            print(f"Ransomware détecté dans {file_path}. Suppression locale...")
            try:
                # Suppression du fichier infecté localement
                os.remove(file_path)
                print(f"Le fichier {file_path} a été supprimé.")
            except Exception as e:
                # En cas d'erreur lors de la suppression du fichier
                print(f"Échec de la suppression du fichier {file_path}. Erreur : {str(e)}")

            print("Téléchargement des fichiers importants sur Google Drive...")
            try:
                # Téléchargement des fichiers importants vers Google Drive
                upload_to_drive(IMPORTANT_DIR)
                # Suppression du dossier après avoir téléchargé les fichiers sur Google Drive
                shutil.rmtree(IMPORTANT_DIR)
                print("Les fichiers importants ont été téléchargés sur Google Drive et supprimés localement.")
            except Exception as e:
                # En cas d'erreur lors du téléchargement des fichiers ou de la suppression du dossier
                print(f"Erreur lors du téléchargement des fichiers ou de la suppression du dossier. Erreur : {str(e)}")

            print(
                "Envisagez de formater votre PC ou consultez un professionnel de l'informatique pour vous assurer que "
                "le ransomware a été complètement éliminé.")
        else:
            # Si aucun ransomware n'est détecté
            print("Aucun ransomware détecté.")

    def scan_file_with_virustotal(self, file_path):
        if use_virustotal:
            # Si l'utilisation de VirusTotal est activée

            # Calculer le hachage du fichier
            file_hash = self.calculate_file_hash(file_path)

            # Vérifier le cache pour les données de numérisation précédentes
            cache_data = self.check_cache(file_hash)

            if cache_data:
                # Si les données de numérisation existent dans le cache, les utiliser
                self.handle_scan_result(cache_data, file_path)
                return cache_data
            else:
                # Sinon, soumettre le fichier à VirusTotal pour analyse

                # URL de numérisation du fichier
                scan_url = 'https://www.virustotal.com/vtapi/v2/file/scan'

                # URL de rapport du fichier
                report_url = 'https://www.virustotal.com/vtapi/v2/file/report'

                # Paramètres de numérisation avec l'API key
                scan_params = {'apikey': self.api_key}

                with open(file_path, 'rb') as file:
                    # Ouvrir le fichier en mode binaire pour la soumission
                    files = {'file': (file_path, file)}

                    # Envoyer la demande de numérisation à VirusTotal
                    scan_response = requests.post(scan_url, files=files, params=scan_params)

                    if scan_response.status_code == 200:
                        # Si la demande de numérisation réussit

                        # Récupérer les données de réponse au format JSON
                        scan_response_data = scan_response.json()

                        print(f'Données de réponse : {scan_response_data}')

                        # Récupérer l'identifiant de ressource (resource) pour récupérer le rapport ultérieurement
                        resource = scan_response_data.get('resource')

                        if resource:
                            # Attendre que VirusTotal analyse le fichier (15 secondes)
                            time.sleep(15)

                            # Paramètres de demande de rapport avec l'API key et l'identifiant de ressource
                            report_params = {'apikey': self.api_key, 'resource': resource}

                            # Envoyer la demande de rapport à VirusTotal
                            report_response = requests.get(report_url, params=report_params)

                            if report_response.status_code == 200:
                                # Si la demande de rapport réussit

                                # Récupérer les données de rapport au format JSON
                                report_response_data = report_response.json()

                                if report_response_data.get('response_code') == 1:
                                    # Enregistrer le résultat dans le cache pour une utilisation ultérieure
                                    self.save_to_cache(file_path, report_response_data)

                                    # Formater et retourner le rapport
                                    return self.format_report(report_response_data)
                                else:
                                    print("Rapport pas encore prêt. Réessayer plus tard.")
                            else:
                                raise Exception("La requête de rapport a échoué avec le code de statut :",
                                                report_response.status_code)
                        else:
                            raise Exception("La clé 'resource' est manquante dans la réponse de numérisation.")
                    else:
                        raise Exception("La requête de numérisation a échoué avec le code de statut :",
                                        scan_response.status_code)
        else:
            # Si l'utilisation de VirusTotal n'est pas activée, retourner None
            return None

    def scan_file_with_metadefender(self, file_path):
        if use_metadefender:
            # Si l'utilisation de MetaDefender est activée

            # Vérifier le cache pour les données de numérisation précédentes
            file_hash = self.calculate_file_hash(file_path)
            cache_data = self.check_cache(file_hash)

            if cache_data:
                # Si les données de numérisation existent dans le cache, les utiliser
                self.handle_scan_result(cache_data, file_path)
                return cache_data
            else:
                # Sinon, soumettre le fichier à MetaDefender pour analyse

                # URL de numérisation du fichier
                scan_url = 'https://api.metadefender.com/v4/file'

                # En-têtes de la requête avec l'API key
                headers = {'apikey': self.api_key}

                with open(file_path, 'rb') as file:
                    # Ouvrir le fichier en mode binaire pour la soumission
                    files = {'file': file}

                    # Envoyer la demande de numérisation à MetaDefender
                    scan_response = requests.post(scan_url, headers=headers, files=files)

                    if scan_response.status_code == 200:
                        # Si la demande de numérisation réussit

                        # Récupérer les données de réponse au format JSON
                        scan_response_data = scan_response.json()

                        print(f'Données de réponse : {scan_response_data}')

                        if 'data_id' in scan_response_data:
                            # Récupérer l'identifiant de données (data_id) pour récupérer le rapport ultérieurement
                            data_id = scan_response_data['data_id']

                            # URL de rapport du fichier spécifique
                            report_url = f'https://api.metadefender.com/v4/file/{data_id}'

                            print(f'Attendre pour les résultats de scan')

                            while True:
                                # Récupérer le rapport de numérisation à partir de MetaDefender
                                report_response = requests.get(report_url, headers=headers)

                                if report_response.status_code == 200:
                                    # Si la demande de rapport réussit

                                    # Récupérer les données de rapport au format JSON
                                    report_response_data = report_response.json()

                                    print(f'Données de rapport : {report_response_data}')

                                    if 'scan_results' in report_response_data:
                                        # Vérifier si les résultats de numérisation sont présents dans le rapport
                                        scan_results = report_response_data['scan_results']

                                        if 'progress_percentage' in scan_results:
                                            # Vérifier si la clé 'progress_percentage'
                                            # est présente dans les résultats de numérisation

                                            progress_percentage = scan_results['progress_percentage']

                                            print(f'Progression de numérisation : {progress_percentage}%')

                                            if progress_percentage == 100:
                                                # Si la numérisation est terminée à 100%

                                                # Enregistrer le résultat dans le cache pour une utilisation ultérieure
                                                self.save_to_cache(file_hash, report_response_data)

                                                # Formater et retourner le rapport
                                                return self.format_report(report_response_data)
                                            else:
                                                # Attendre 15 secondes et réessayer tant que l'analyse nest pas terminée
                                                time.sleep(15)
                                        else:
                                            raise Exception(
                                                "La clé 'progress_percentage' est manquante dans les 'scan_results'.")
                                    else:
                                        raise Exception(
                                            "La clé 'scan_results' est manquante dans la réponse de rapport.")
                                else:
                                    raise Exception(
                                        f"La requête de rapport a échoué avec "
                                        f"le code de statut : {report_response.status_code}")
                        else:
                            raise Exception("La clé 'data_id' est manquante dans la réponse de numérisation.")
                    else:
                        raise Exception(
                            f"La requête de numérisation a échoué avec le code de statut : {scan_response.status_code}")
        else:
            # Si l'utilisation de MetaDefender est désactivée
            return None

    def scan_file_with_hybridanalysis(self, file_path):
        if use_hybridanalysis:
            # Vérifier le cache
            cache_data = self.check_cache(file_path)
            if cache_data:
                self.handle_scan_result(False, file_path)
                return cache_data

            # Soumettre le fichier à l'analyse
            scan_url = 'https://www.hybrid-analysis.com/api/v2/submit/file'
            headers = {'api-key': self.api_key}
            with open(file_path, 'rb') as file:
                files = {'file': (file_path, file)}
                scan_response = requests.post(scan_url, headers=headers, files=files)

            if scan_response.status_code == 200:
                scan_response_data = scan_response.json()
                print(f'Response data: {scan_response_data}')

                if 'threat_score' in scan_response_data:
                    threat_score = scan_response_data['threat_score']
                    report_url = f'https://www.hybrid-analysis.com/api/v2/report/{threat_score}/summary'
                    print(f'Attente pour les résultats des scan')

                    while True:
                        time.sleep(20)
                        report_response = requests.get(report_url, headers=headers)

                        if report_response.status_code == 200:
                            report_response_data = report_response.json()
                            print(f'Report data: {report_response_data}')

                            """if 'summary' in report_response_data:
                                summary = report_response_data['summary']
                                if 'progress_percentage' in summary:
                                    progress_percentage = summary['progress_percentage']
                                    print(f'Scan progress: {progress_percentage}%')

                                    if progress_percentage == 100:
                                        if 'detection_count' in summary:
                                            detection_count = summary['detection_count']
                                            if detection_count == 0:
                                                # Enregistrer le résultat dans le cache pour une utilisation ultérieure
                                                self.save_to_cache(file_path, report_response_data)
                                                self.handle_scan_result(False, file_path)
                                                return self.format_report(report_response_data)
                                            else:
                                                self.handle_scan_result(True, file_path)
                                                return self.format_report(report_response_data)
                                        else:
                                            raise Exception(
                                                "La clé 'detection_count' est manquante dans les 'summary'.")
                                    else:
                                        # Attendre et réessayer tant que l'analyse n'est pas terminée
                                        time.sleep(15)
                                else:
                                    raise Exception("La clé 'progress_percentage' est manquante dans les 'summary'.")
                            else:
                                raise Exception("La clé 'summary' est manquante dans la réponse de rapport.")
                        else:
                            raise Exception("La requête de rapport a échoué avec le code de statut :",
                                            report_response.status_code)
                else:
                    raise Exception("La clé 'job_id' est manquante dans la réponse de numérisation.")
            else:
                raise Exception("La requête de numérisation a échoué avec le code de statut :",
                                scan_response.status_code)"""
            else:
                print("Aucun ransomware détecté")
                raise Exception("HybridAnalysis : Aucun ransomware détecté")

        else:
            return None

    def format_report(self, report_response_data):
        if 'lookup_results' in report_response_data:
            # Si les résultats de recherche sont présents dans les données de rapport
            lookup_results = report_response_data['lookup_results']
            return self.format_report_link(lookup_results)
        elif 'response_code' in report_response_data:
            # Si le code de réponse est présent dans les données de rapport
            if report_response_data['response_code'] == 1:
                # Si le code de réponse indique une analyse réussie
                if 'positives' in report_response_data and report_response_data['positives'] > 0:
                    # Si des positifs (detections) sont trouvés
                    self.handle_scan_result(True, report_response_data)
                    return "Le fichier est détecté comme ransomware."
                else:
                    # Si aucun positif (detection) n'est trouvé
                    self.handle_scan_result(False, report_response_data)
                    return "Le fichier n'est pas détecté comme ransomware."
            else:
                return "Erreur lors de l'analyse du fichier."
        elif 'scan_results' in report_response_data:
            # Si les résultats de numérisation sont présents dans les données de rapport
            scan_results = report_response_data['scan_results']
            return self.format_report_file(scan_results)
        else:
            raise Exception('MetaDefender : Aucun ransomware détecté')

    def format_report_link(self, lookup_results):
        detected_by = lookup_results.get('detected_by', 0)
        if detected_by > 0:
            # Si au moins une source a détecté un problème, on considère que le lien est dangereux
            self.handle_scan_result(True, lookup_results)
            return "Le lien est détecté comme ransomware."
        else:
            # Si aucune source n'a détecté de problème, le lien est considéré comme sûr
            self.handle_scan_result(False, lookup_results)
            return "Le lien n'est pas détecté comme ransomware."

    def format_report_file(self, scan_results):
        if 'progress_percentage' in scan_results:
            # Si la clé 'progress_percentage' est présente dans les résultats de numérisation
            progress_percentage = scan_results['progress_percentage']
            print(f'Progression de numérisation : {progress_percentage}%')
            if progress_percentage == 100:
                if 'scan_all_result_a' in scan_results:
                    scan_result = scan_results['scan_all_result_a']
                    print(f'Résultat de numérisation : {scan_result}')  # Imprimer le résultat de numérisation

                    # Si un ransomware est détecté par MetaDefender
                    if 'scan_details' in scan_results:
                        for scanner in scan_results['scan_details']:
                            if 'threat_found' in scan_results['scan_details'][scanner] and \
                                    scan_results['scan_details'][scanner]['threat_found']:
                                self.handle_scan_result(True, scan_results)
                                return f"Le fichier est détecté comme ransomware par {scanner}."

                    # Si aucun ransomware n'est détecté
                    self.handle_scan_result(False, scan_results)
                    return "Le fichier n'est pas détecté comme ransomware."
                else:
                    raise Exception("La clé 'scan_all_result_a' est manquante dans les 'scan_results'.")
            else:
                return "L'analyse du fichier est en cours. Veuillez réessayer plus tard."
        else:
            raise Exception("La clé 'progress_percentage' est manquante dans les 'scan_results'.")

    def scan_link_with_virustotal(self, link):
        if use_virustotal:
            # Vérifier si l'utilisation de VirusTotal est activée

            # URL de numérisation pour soumettre un lien URL
            scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan'

            # URL de rapport pour obtenir les résultats de l'analyse
            report_url = 'https://www.virustotal.com/vtapi/v2/url/report'

            # Paramètres de numérisation avec l'API key et l'URL
            scan_params = {'apikey': self.api_key, 'url': link}

            # Envoyer la demande de numérisation à VirusTotal
            scan_response = requests.post(scan_url, params=scan_params)

            if scan_response.status_code == 200:
                # Si la demande de numérisation réussit

                # Récupérer les données de réponse au format JSON
                scan_response_data = scan_response.json()
                scan_id = scan_response_data.get('scan_id')

                if scan_id:
                    # Vérifier si l'ID de numérisation est présent dans les données de réponse

                    # Paramètres de rapport avec l'API key et l'ID de numérisation
                    report_params = {'apikey': self.api_key, 'resource': scan_id}

                    # Envoyer la demande de rapport à VirusTotal
                    report_response = requests.get(report_url, params=report_params)

                    if report_response.status_code == 200:
                        # Si la demande de rapport réussit

                        # Récupérer les données de rapport au format JSON
                        report_response_data = report_response.json()

                        # Enregistrer le résultat dans le cache pour une utilisation ultérieure
                        self.save_to_cache(link, report_response_data)

                        # Formater et retourner le rapport
                        return self.format_report(report_response_data)
                    else:
                        raise Exception("La requête de rapport a échoué avec le code de statut :",
                                        report_response.status_code)
                else:
                    raise Exception("La clé 'scan_id' est manquante dans la réponse de numérisation.")
            else:
                raise Exception("La requête de numérisation a échoué avec le code de statut :",
                                scan_response.status_code)
        else:
            # Si l'utilisation de VirusTotal est désactivée
            return None

    @staticmethod
    def save_result_to_file(result, link):
        cleaned_link = re.sub(r'[\\/:*?"<>|]', '', link)  # Supprimer les caractères non valides
        filename = f"C:\\Users\\natha\\Documents\\Fichiers_Tri\\{cleaned_link}.json"
        with open(filename, 'w') as f:
            json.dump(result, f)

    def scan_link_with_metadefender(self, link):
        if use_metadefender:
            # Vérifier le cache pour les données de numérisation précédentes
            cache_data = self.check_cache(link)

            if cache_data:
                # Si les données de numérisation existent dans le cache, les utiliser
                self.handle_scan_result(cache_data, link)
                return cache_data
            else:
                # URL de numérisation pour soumettre un lien URL
                scan_url = 'https://api.metadefender.com/v4/url'

                # En-têtes de la requête avec l'API key et le type de contenu
                headers = {'apikey': self.api_key, 'Content-Type': 'application/json'}

                # Données de numérisation avec le lien URL converti en un tableau
                scan_data = {'url': [link]}

                # Envoyer la demande de numérisation à MetaDefender
                scan_response = requests.post(scan_url, headers=headers, data=json.dumps(scan_data))

                print(f"Réponse de numérisation : {scan_response.text}")  # Ajout d'un point de journalisation

                if scan_response.status_code == 200:
                    # Si la demande de numérisation réussit

                    # Récupérer les données de réponse au format JSON
                    scan_response_data = scan_response.json()
                    data = scan_response_data.get('data')[0]

                    if data:
                        # Vérifier si les données sont présentes dans la réponse
                        lookup_results = data.get('lookup_results')

                        if lookup_results:
                            # Si les résultats de recherche sont présents dans les données
                            print(f'Résultats de recherche : {lookup_results}')

                            # Enregistrer le résultat dans un fichier
                            self.save_result_to_file(lookup_results, link)

                            # Formater et afficher le rapport
                            report = self.format_report(lookup_results)
                            print(report)
                            return lookup_results
                    else:
                        raise Exception("La clé 'data' est manquante dans la réponse de numérisation.")
                else:
                    raise Exception(
                        f"La requête de numérisation a échoué avec le code de statut : {scan_response.status_code}")
        else:
            # Si l'utilisation de MetaDefender est désactivée
            return None

    def scan_link_with_hybridanalysis(self, link):
        if use_hybridanalysis:
            # Vérifier le cache pour les données de numérisation précédentes
            cache_data = self.check_cache(link)

            if cache_data:
                # Si les données de numérisation existent dans le cache, les utiliser
                self.handle_scan_result(cache_data, link)
                return cache_data
            else:
                # URL de numérisation pour soumettre un lien URL
                scan_url = 'https://www.hybrid-analysis.com/api/v2/submit/link'

                # En-têtes de la requête avec l'API key et le type de contenu
                headers = {'apikey': self.api_key, 'Content-Type': 'application/json'}

                # Données de numérisation avec le lien URL converti en un tableau
                data = {'url': [link]}

                # Envoyer la demande de numérisation à Hybrid Analysis
                scan_response = requests.post(scan_url, headers=headers, json=data)
                print(f"Réponse de numérisation : {scan_response.text}")  # Ajout d'un point de journalisation

                if scan_response.status_code == 200:
                    # Si la demande de numérisation réussit

                    # Récupérer les données de réponse au format JSON
                    scan_response_data = scan_response.json()
                    job_id = scan_response_data.get('job_id')

                    if job_id:
                        # Vérifier si l'ID de travail est présent dans la réponse
                        report_url = f'https://www.hybrid-analysis.com/api/v2/report/{job_id}/summary'

                        # Ajouter l'en-tête User-Agent requis pour le rapport
                        headers['User-Agent'] = 'Falcon Sandbox'

                        # Récupérer le rapport de numérisation via Hybrid Analysis
                        report_response = requests.get(report_url, headers=headers)

                        if report_response.status_code == 200:
                            # Si la demande de rapport réussit

                            # Récupérer les données de rapport au format JSON
                            report_response_data = report_response.json()
                            lookup_results = report_response_data.get('lookup_results')

                            if lookup_results:
                                # Si les résultats de recherche sont présents dans les données
                                print(f'Résultats de recherche : {lookup_results}')

                                # Enregistrer le résultat dans un fichier
                                self.save_result_to_file(lookup_results, link)

                                # Gérer le résultat de la numérisation (ransomware détecté)
                                self.handle_scan_result(True, link)

                                # Formater et afficher le rapport
                                report = self.format_report(lookup_results)
                                print(report)
                                return lookup_results
                            else:
                                raise Exception(
                                    "La clé 'lookup_results' est manquante dans la réponse de numérisation.")
                        else:
                            raise Exception(
                                f"La requête de rapport a échoué avec le code de statut : {report_response.status_code}"
                            )
                    else:
                        raise Exception("La clé 'job_id' est manquante dans la réponse de numérisation.")
                else:
                    raise Exception(
                        f"La requête de numérisation a échoué avec le code de statut : {scan_response.status_code}"
                    )
        else:
            # Si l'utilisation de Hybrid Analysis est désactivée
            return None

    @staticmethod
    def calculate_file_hash(file_path):
        # Calculer le hash SHA256 d'un fichier
        with open(file_path, 'rb') as file:
            file_data = file.read()
            file_hash = hashlib.sha256(file_data).hexdigest()
        return file_hash

    def check_cache(self, file_hash):
        # Vérifier si le résultat d'analyse du fichier est déjà dans le cache
        cache_file = os.path.join(self.cache_dir, file_hash + '.json')
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as file:
                cache_data = json.load(file)
            return cache_data
        return None

    def save_to_cache(self, file_path, report_response_data):
        # Obtenez le nom du fichier à partir du chemin du fichier
        file_name = os.path.basename(file_path)
        # Générer un nom de fichier unique en ajoutant un horodatage au nom du fichier
        timestamp = time.strftime('%Y%m%d%H%M%S', time.localtime())
        unique_file_name = f"{file_name}_{timestamp}.json"
        # Construire le chemin complet du fichier à enregistrer dans le cache
        cache_file = os.path.join(self.cache_dir, unique_file_name)
        with open(cache_file, 'w') as file:
            json.dump(report_response_data, file)


def select_analyzers():
    global use_check, use_virustotal, use_metadefender, use_hybridanalysis

    # Créer une fenêtre de sélection des analyseurs
    analyzer_window = tk.Toplevel(window)
    analyzer_window.title("Sélection des Analyseurs")

    # Variables pour les cases à cocher
    use_check_var = tk.BooleanVar(value=use_check)
    use_virustotal_var = tk.BooleanVar(value=use_virustotal)
    use_metadefender_var = tk.BooleanVar(value=use_metadefender)
    use_hybridanalysis_var = tk.BooleanVar(value=use_hybridanalysis)

    # Créer les cases à cocher pour chaque analyseur
    check_checkbox = tk.Checkbutton(analyzer_window, text="Un seul analyseur à la fois",
                                    font=("Montserrat", 10, "italic bold"), variable=use_check_var)
    virustotal_checkbox = tk.Checkbutton(analyzer_window, text="VirusTotal", variable=use_virustotal_var)
    metadefender_checkbox = tk.Checkbutton(analyzer_window, text="MetaDefender", variable=use_metadefender_var)
    hybridanalysis_checkbox = tk.Checkbutton(analyzer_window, text="HybridAnalysis", variable=use_hybridanalysis_var)

    # Afficher les cases à cocher
    check_checkbox.pack()
    virustotal_checkbox.pack()
    metadefender_checkbox.pack()
    hybridanalysis_checkbox.pack()

    # Définir une fonction pour mettre à jour les variables de sélection des analyseurs
    def update_selection():
        global use_check, use_virustotal, use_metadefender, use_hybridanalysis
        use_check = use_check_var.get()
        use_virustotal = use_virustotal_var.get()
        use_metadefender = use_metadefender_var.get()
        use_hybridanalysis = use_hybridanalysis_var.get()

    # Définir une fonction pour fermer la fenêtre de sélection des analyseurs
    def close_window():
        update_selection()
        analyzer_window.destroy()

    # Créer un bouton pour fermer la fenêtre
    close_button = tk.Button(analyzer_window, text="Fermer", command=close_window)
    close_button.pack()


def upload_to_drive(folder_path):
    # Authentification à Google Drive
    drive_gauth = GoogleAuth()
    drive_gauth.CommandLineAuth()
    # Vérifier si l'authentification a réussi
    if drive_gauth.access_token:
        # Créer une instance de GoogleDrive avec l'authentification réussie
        drive = GoogleDrive(drive_gauth)

        # Parcourir les fichiers dans le dossier spécifié
        for file_name in os.listdir(folder_path):
            # Construire le chemin complet du fichier
            file_path = os.path.join(folder_path, file_name)

            # Créer un objet de fichier Google Drive avec le nom du fichier
            gfile = drive.CreateFile({'title': file_name})

            # Définir le contenu du fichier à partir du fichier local
            gfile.SetContentFile(file_path)

            # Télécharger le fichier vers Google Drive
            gfile.Upload()

            # Afficher un message indiquant que le fichier a été téléchargé avec succès
            print(f'{file_name} a été parfaitement téléchargé.')
    else:
        print("L'authentification a échoué.")


def get_last_file(folder_path):
    files = os.listdir(folder_path)
    files = [file for file in files if
             os.path.isfile(os.path.join(folder_path, file))]  # Filtrer uniquement les fichiers
    if files:
        files.sort(key=lambda x: os.path.getmtime(os.path.join(folder_path, x)),
                   reverse=True)  # Trier les fichiers par date de modification (du plus récent au plus ancien)
        last_file = os.path.join(folder_path, files[0])  # Récupérer le dernier fichier de la liste
        return last_file
    else:
        return None


def save():
    # Utilisation de la fonction get_last_file pour récupérer le dernier fichier dans le répertoire "fichier_tri"
    folder_path = r'C:\Users\natha\Documents\Fichiers_Tri'
    # Remplacez par le chemin réel vers le répertoire "fichier_tri"
    last_file = get_last_file(folder_path)
    # Ouvrir la boîte de dialogue "Enregistrer sous" avec le chemin par défaut
    file_path = filedialog.asksaveasfilename(initialdir=r'C:\Users\natha\Documents\Fichiers_Tri',
                                             defaultextension='.json')

    # Copier le dernier fichier envoyé vers l'emplacement choisi
    if last_file and file_path:
        try:
            shutil.copy(last_file, file_path)
            messagebox.showinfo("Enregistrement", "Le fichier ou le lien a été enregistré avec succès.")
        except Exception as e:
            messagebox.showerror("Erreur",
                                 f"Une erreur s'est produite lors de l'enregistrement du fichier ou du lien: {str(e)}")
    else:
        messagebox.showwarning("Aucun fichier", "Aucun fichier ou lien n'a été envoyé pour l'enregistrer.")


def option():
    print("Vous avez cliqué sur le sous-onglet : Modifier la taille")


def select_file():
    # Fonction pour ouvrir une fenêtre de sélection de fichier
    file_path = filedialog.askopenfilename()

    # Initialiser les scanners pour chaque API
    scanner1 = FileScanner(VIRUSTOTAL_API_KEY)
    scanner2 = FileScanner(METADEFENDER_API_KEY)
    scanner3 = FileScanner(HYBRIDANALYSIS_API_KEY)

    def handle_results(result, scanner_name):
        # Fonction de rappel pour afficher les résultats de l'analyse
        result_label.config(text=f"{scanner_name}: {result}")

    def scan_file(file_path, scanner, scanner_name):
        try:
            if scanner_name == "VirusTotal":
                result = scanner.scan_file_with_virustotal(file_path)
            elif scanner_name == "MetaDefender":
                result = scanner.scan_file_with_metadefender(file_path)
            elif scanner_name == "HybridAnalysis":
                result = scanner.scan_file_with_hybridanalysis(file_path)
            else:
                raise Exception("Analyseur non pris en charge")

            # Appeler la fonction de rappel pour afficher les résultats
            window.after(0, handle_results, result, scanner_name)
        except Exception as e:
            result_label.config(text=str(e))

    # Lancer les analyses dans des threads séparés
    thread1 = threading.Thread(target=scan_file, args=(file_path, scanner1, "VirusTotal"))
    thread2 = threading.Thread(target=scan_file, args=(file_path, scanner2, "MetaDefender"))
    thread3 = threading.Thread(target=scan_file, args=(file_path, scanner3, "HybridAnalysis"))

    thread1.start()
    thread2.start()
    thread3.start()


def select_link():
    # Fonction pour obtenir le lien URL entré par l'utilisateur et l'analyser
    link = link_entry.get()

    # Initialiser les scanners pour chaque API
    scanner1 = FileScanner(VIRUSTOTAL_API_KEY)
    scanner2 = FileScanner(METADEFENDER_API_KEY)
    scanner3 = FileScanner(HYBRIDANALYSIS_API_KEY)

    def handle_results(result, scanner_name):
        # Fonction de rappel pour afficher les résultats de l'analyse
        result_label.config(text=f"{scanner_name}: {result}")

    def scan_link(link, scanner, scanner_name):
        try:
            if scanner_name == "VirusTotal":
                result = scanner.scan_link_with_virustotal(link)
            elif scanner_name == "MetaDefender":
                result = scanner.scan_link_with_metadefender(link)
            elif scanner_name == "HybridAnalysis":
                result = scanner.scan_link_with_hybridanalysis(link)
            else:
                raise Exception("Analyseur non pris en charge")

            # Appeler la fonction de rappel pour afficher les résultats
            window.after(0, handle_results, result, scanner_name)
        except Exception as e:
            result_label.config(text=str(e))

    # Lancer les analyses dans des threads séparés
    thread1 = threading.Thread(target=scan_link, args=(link, scanner1, "VirusTotal"))
    thread2 = threading.Thread(target=scan_link, args=(link, scanner2, "MetaDefender"))
    thread3 = threading.Thread(target=scan_link, args=(link, scanner3, "Hybrid Analysis"))

    thread1.start()
    thread2.start()
    thread3.start()


def select_file_and_upload():
    # Fonction pour sélectionner un fichier et le télécharger sur Google Drive
    file_path = filedialog.askopenfilename()  # Sélectionner un fichier à partir de l'explorateur de fichiers
    file_name = os.path.basename(file_path)  # Récupérer le nom du fichier à partir du chemin complet
    gfile = drive.CreateFile({'title': file_name, 'parents': [{'id': parent_folder_id}]})
    # Créer un objet GoogleDriveFile avec le nom du fichier et l'ID du dossier parent
    gfile.SetContentFile(file_path)  # Définir le contenu du fichier à télécharger
    gfile.Upload()  # Télécharger le fichier sur Google Drive
    success_message.set(f"{file_name} a été téléchargé avec succès.")


def select_file_and_upload_wrapper():
    # Fonction d'enveloppe pour appeler la fonction de sélection de fichier puis la fonction de téléchargement
    select_file()  # Appeler la fonction de sélection de fichier pour choisir un fichier
    select_file_and_upload()  # Appeler la fonction de téléchargement du fichier sélectionné sur Google Drive


# Variable pour garder la trace de l'état de la taille de la fenêtre
is_window_small = False


def resize_window():
    global is_window_small
    if is_window_small:
        window.geometry('1000x1000')  # Rétablir la taille d'origine
        is_window_small = False
    else:
        window.geometry('850x850')  # Rendre la fenêtre plus petite
        is_window_small = True

    new_window = tk.Toplevel(window)
    new_window.title('Aide')
    lbl = tk.Label(new_window, text='Vous pouvez modifier la taille de la fenêtre en glissant les bords de celle-ci.')
    lbl.pack()


def minimum_size():
    window.geometry(
        '700x700')  # Définit la taille minimale de la fenêtre à 700 pixels de largeur et 700 pixels de hauteur.


# Initialisation de l'authentification GoogleDrive
gauth = GoogleAuth()
gauth.LocalWebserverAuth()

drive = GoogleDrive(gauth)

# ID du dossier parent sur Google Drive
parent_folder_id = "1SG3dXeXNavcu-IA-NSK2ycWiTEd8LeHl"


# Création de l'interface graphique
# Créer la fenêtre principale

def show_error(message):
    messagebox.showerror("Erreur", message)


window = tk.Tk()
window.title("Protection contre les ransomwares")
window.geometry("1000x1000")
window.iconbitmap('Logo1.ico')

style = ttk.Style()

# Configure le thème personnalisé pour supprimer les arrière-plans blancs
style.configure('Custom.TFrame', background="#001233")
style.configure('Custom.TLabel', background="#13283c", foreground="white", padding=(10, 10))
style.configure('Custom.TButton', background="#FF595A", foreground="white")

frame_image = Image.open('ataques-ransomware.jpeg')
frame_photo = ImageTk.PhotoImage(frame_image)
frame_label = tk.Label(window, border=0, image=frame_photo)
frame_label.place(x=0, y=0)

title_label = ttk.Label(window, text='SoteriaScan', font=("Montserrat", 35, "italic bold"), style='Custom.TLabel')

logo_image = tk.PhotoImage(file="Logo1.png")
logo_label = ttk.Label(window, image=logo_image, style='Custom.TLabel')

file_shadow = ttk.Frame(window, style='Custom.TFrame')
file_box = ttk.Frame(file_shadow, style='Custom.TFrame')

select_file_button = ttk.Button(file_box, text="Sélectionner un fichier", style='Custom.TButton', command=select_file)

select_button = ttk.Button(file_box, text="Sélectionner un fichier à analyser et envoyer au Drive",
                           style='Custom.TButton', command=select_file_and_upload_wrapper)

link_shadow = ttk.Frame(window, style='Custom.TFrame')
link_box = ttk.Frame(link_shadow, style='Custom.TFrame')

link_entry = ttk.Entry(link_box)

select_link_button = ttk.Button(link_box, text="Analyser le lien", style='Custom.TButton', command=select_link)

result_label = ttk.Label(window, text="Résultat de l'analyse", font=("Montserrat", 15, "italic bold"),
                         style='Custom.TLabel')

success_frame = ttk.Frame(window, style='Custom.TFrame')
success_message = tk.StringVar()
success_message.set("Le message de réussite s'obtient ici")

success_label = ttk.Label(success_frame, textvariable=success_message, font=("Montserrat", 15, "italic bold"),
                          style='Custom.TLabel')

for i in range(50):  # Configure grid to make it responsive
    window.grid_rowconfigure(i, weight=1)
    window.grid_columnconfigure(i, weight=1)

# Add everything to grid instead of using pack
logo_label.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=(10, 0), rowspan=1)
title_label.grid(row=0, column=1, sticky="w", padx=(50, 0), pady=(100, 200))

file_shadow.grid(row=1, column=1, sticky="nsew", padx=(10, 0), pady=(10, 0))
file_box.grid(row=0, column=0, sticky="nsew")
select_file_button.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
select_button.grid(row=1, column=0, sticky="nsew", pady=(0, 10))

link_shadow.grid(row=2, column=1, sticky="nsew", padx=(10, 0), pady=(10, 0))
link_box.grid(row=0, column=0, sticky="nsew")
link_entry.grid(row=0, column=0, sticky="nsew", pady=(10, 0))
select_link_button.grid(row=0, column=1, sticky="nsew", pady=(10, 0))

result_label.grid(row=3, column=1, sticky="w", padx=(10, 0), pady=(10, 0))

success_frame.grid(row=4, column=1, sticky="nsew", padx=(10, 0), pady=(10, 0))
success_label.grid(row=0, column=0, sticky="nsew")

window.configure(background="#13283c")

menu_bar = tk.Menu(window)
file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Enregistrer sous", command=save)
menu_bar.add_cascade(label="Lien", menu=file_menu)
window.config(menu=menu_bar)

fichier = tk.Menu(menu_bar, tearoff=0)
fichier.add_command(label="Enregistrer sous", command=save)

option = tk.Menu(menu_bar, tearoff=0)
option.add_command(label="Modifier la taille", command=resize_window)
option.add_command(label="Taille minimale", command=minimum_size)
option.add_command(label="Sélectionner les analyseurs", command=select_analyzers)

menu_bar.add_cascade(label="Fichier", menu=fichier)
menu_bar.add_cascade(label="Options", menu=option)
window.config(menu=menu_bar)
window.mainloop()
