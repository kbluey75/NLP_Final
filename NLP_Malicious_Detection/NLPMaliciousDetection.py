# -*- coding: utf-8 -*-
import os
import json
import subprocess

from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter, FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.datamodel import BlackboardArtifact, BlackboardAttribute
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.datamodel import ReadContentInputStream
from java.io import FileOutputStream, BufferedInputStream
from java.lang import System
from jarray import zeros

class NLPExternalWrapperIngestModuleFactory(IngestModuleFactoryAdapter):

    def getModuleDisplayName(self):
        return "NLP Malicious Detection"

    def getModuleDescription(self):
        return "Calls external Python 3 script to analyze text files for inappropriate content."

    def getModuleVersionNumber(self):
        return "1.0"

    def isFileIngestModuleFactory(self):
        return True

    def createFileIngestModule(self, ingestJobContext):
        return NLPExternalWrapperIngestModule()

class NLPExternalWrapperIngestModule(FileIngestModule):

    def startUp(self, context):
        self.context = context
        self.python_exe = "C:/Users/Kaden/AppData/Local/Programs/Python/Python310/python.exe"
        self.script_path = os.path.join(os.path.dirname(__file__), "nlp_final.py")
        self.log("Startup complete. Using script: {}".format(self.script_path))

    def process(self, file):
        try:
            self.log("Processing file: {}".format(file.getName()))

            if file.getSize() == 0 or file.isDir():
                self.log("Skipping (empty or dir): {}".format(file.getName()))
                return IngestModule.ProcessResult.OK

            name_lower = file.getName().lower()
            if not (name_lower.endswith(".txt") or name_lower.endswith(".pdf") or
                    name_lower.endswith(".docx") or name_lower.endswith(".eml")):
                self.log("Skipping (unsupported extension): {}".format(file.getName()))
                return IngestModule.ProcessResult.OK

            # Dump file to temp path
            temp_path = os.path.join(System.getProperty("java.io.tmpdir"), file.getName())
            input_stream = BufferedInputStream(ReadContentInputStream(file))
            output_stream = FileOutputStream(temp_path)
            buffer = zeros(8192, 'b')
            bytes_read = input_stream.read(buffer)
            while bytes_read != -1:
                output_stream.write(buffer, 0, bytes_read)
                bytes_read = input_stream.read(buffer)
            input_stream.close()
            output_stream.close()

            self.log("Wrote temp file: {}".format(temp_path))

            # Run Python script
            command = [self.python_exe, self.script_path, temp_path]
            self.log("Running script: {}".format(" ".join(command)))

            result = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            self.log("Script output:\n{}".format(result))

            json_data = json.loads(result)

            if json_data.get("status") == "ok" and json_data.get("artifacts"):
                blackboard = Case.getCurrentCase().getServices().getBlackboard()

                # Register custom artifact and attribute types
                try:
                    artifact_type = blackboard.getOrAddArtifactType("TSK_NLP_FLAGGED", "Flagged Content")
                    artifact_type_id = artifact_type.getTypeID()
                    attr_type = blackboard.getOrAddAttributeType("TSK_MATCHED_TERMS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Matched Terms")
                    attr_type_id = attr_type.getTypeID()
                    self.log("Registered custom artifact/attribute types")
                except:
                    self.log("Artifact or attribute already registered")
                    artifact_type = blackboard.getArtifactType("TSK_NLP_FLAGGED")
                    artifact_type_id = artifact_type.getTypeID()
                    attr_type = blackboard.getAttributeType("TSK_MATCHED_TERMS")
                    attr_type_id = attr_type.getTypeID()

                for artifact_data in json_data["artifacts"]:
                    art = file.newArtifact(artifact_type_id)
                    attributes = artifact_data.get("attributes", {})

                    for attr_name, attr_value in attributes.items():
                        try:
                            if attr_name == "TSK_NAME":
                                art.addAttribute(BlackboardAttribute(
                                    BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, "NLP Module", attr_value))
                            elif attr_name == "TSK_COMMENT":
                                art.addAttribute(BlackboardAttribute(
                                    BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT, "NLP Module", attr_value))
                            elif attr_name == "TSK_MATCHED_TERMS":
                                art.addAttribute(BlackboardAttribute(attr_type_id, "NLP Module", attr_value))
                            else:
                                self.log("Unknown attribute: {} = {}".format(attr_name, attr_value))
                        except Exception as e:
                            self.log("Attribute error: {} = {} | {}".format(attr_name, attr_value, str(e)))

                    blackboard.indexArtifact(art)
                    self.log("Posted custom artifact for: {}".format(file.getName()))
            else:
                self.log("Script returned no artifacts or non-ok status.")

        except Exception as e:
            self.log("ERROR: {}".format(str(e)))

        return IngestModule.ProcessResult.OK

    def log(self, msg):
        try:
            with open(os.path.expanduser("~/nlp_jython_log.txt"), "a") as f:
                f.write(msg + "\n")
        except:
            pass

