import sys
import Cocoa
import Vision
import Quartz

def recognize_text(image_path):
    # Load the image
    image_url = Cocoa.NSURL.fileURLWithPath_(image_path)
    handler = Vision.VNImageRequestHandler.alloc().initWithURL_options_(image_url, None)
    
    # Store results
    extracted_text = []
    
    def recognition_handler(request, error):
        if error:
            print(f"Error: {error}")
            return
        results = request.results()
        for observation in results:
            top_candidate = observation.topCandidates_(1).firstObject()
            if top_candidate:
                extracted_text.append(top_candidate.string())

    request = Vision.VNRecognizeTextRequest.alloc().initWithCompletionHandler_(recognition_handler)
    
    # Use accurate recognition (uses Neural Engine heavily)
    request.setRecognitionLevel_(Vision.VNRequestTextRecognitionLevelAccurate)
    
    try:
        handler.performRequests_error_([request], None)
        return " // ".join(extracted_text)
    except Exception as e:
        print(f"Failed: {e}")
        return None

if __name__ == "__main__":
    out = recognize_text("qr_network.png") # We happen to have this file as a dummy image
    print("Test Output:", out)
