class InvalidSignatureException(Exception):
    def __init__(self, id):
        self.message = "Signature verification failed for voter " + str(id)
        super().__init__(self.message)


class InvalidProofException(Exception):
    def __init__(self, id):
        self.message = (
            "Trapdoor keypair proof verification failed for voter " + str(id)
        )
        super().__init__(self.message)


class InvalidWFNProofException(Exception):
    def __init__(self, id):
        self.message = (
            "Well-formedness proof verification failed for voter " + str(id)
        )
        super().__init__(self.message)
