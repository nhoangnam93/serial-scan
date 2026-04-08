import sys
import Cocoa
import Vision

def test_img(path):
    with open(path, 'rb') as f:
        img_data = f.read()
    ns_data = Cocoa.NSData.dataWithBytes_length_(img_data, len(img_data))
    handler = Vision.VNImageRequestHandler.alloc().initWithData_options_(ns_data, None)
    extracted_text = []

    def recognition_handler(req, error):
        if error: return
        res = req.results()
        if not res: return
        for obs in res:
            top_candidate = obs.topCandidates_(1).firstObject()
            if top_candidate:
                extracted_text.append(top_candidate.string())

    request = Vision.VNRecognizeTextRequest.alloc().initWithCompletionHandler_(recognition_handler)
    request.setRecognitionLevel_(Vision.VNRequestTextRecognitionLevelAccurate)
    
    handler.performRequests_error_([request], None)
    return " ".join(extracted_text)

print(test_img(sys.argv[1]))
