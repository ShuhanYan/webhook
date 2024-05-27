package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
)

var ignoredNamespaces = []string{
	metav1.NamespaceSystem,
	metav1.NamespacePublic,
}

const (
	admissionWebhookAnnotationInjectKey = "sidecar-injector-webhook.morven.me/inject"
	admissionWebhookAnnotationStatusKey = "sidecar-injector-webhook.morven.me/status"
)

type WebhookServer struct {
	sidecarConfig *Config
	server        *http.Server
}

// Webhook Server parameters
type WhSvrParameters struct {
	port           int    // webhook server port
	certFile       string // path to the x509 certificate for https
	keyFile        string // path to the x509 private key matching `CertFile`
	sidecarCfgFile string // path to sidecar injector configuration file
}

type Config struct {
	Containers []corev1.Container `yaml:"containers"`
	Volumes    []corev1.Volume    `yaml:"volumes"`
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func loadConfig(configFile string) (*Config, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	infoLogger.Printf("New configuration: sha256sum %x", sha256.Sum256(data))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Check whether the target resoured need to be mutated
func mutationRequired(ignoredList []string, metadata *metav1.ObjectMeta) bool {
	// skip special kubernete system namespaces
	for _, namespace := range ignoredList {
		if metadata.Namespace == namespace {
			infoLogger.Printf("Skip mutation for %v for it's in special namespace:%v", metadata.Name, metadata.Namespace)
			return false
		}
	}

	annotations := metadata.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	status := annotations[admissionWebhookAnnotationStatusKey]

	// determine whether to perform mutation based on annotation for the target resource
	var required bool
	if strings.ToLower(status) == "injected" {
		required = false
	} else {
		switch strings.ToLower(annotations[admissionWebhookAnnotationInjectKey]) {
		default:
			required = true
		case "n", "not", "false", "off":
			required = false
		}
	}

	infoLogger.Printf("Mutation policy for %v/%v: status: %q required:%v", metadata.Namespace, metadata.Name, status, required)
	return required
}

func addContainerResource(target []corev1.Container) (patch []patchOperation) {
	for i, t := range target {
		// if t.Name == "init-config" {
		// 	patch = append(patch, patchOperation{
		// 		Op:    "replace",
		// 		Path:  fmt.Sprintf("/spec/initContainers/%d/image", i),
		// 		Value: "k8stage.azurecr.io/k8s/k8-lnx_job_interactive:1.0.0.0-DESKTOP-2FTJPM4",
		// 	})
		// }
		if t.Name == "job" {
			value := t.Resources.Limits
			// q, _ := resource.ParseQuantity("44")
			// value["cpu"] = q
			// sq, _ := resource.ParseQuantity("30Gi")
			// value["ephemeral-storage"] = sq
			mq, _ := resource.ParseQuantity("25Gi")
			value["memory"] = mq
			// gq, _ := resource.ParseQuantity("1")
			// value["nvidia.com/gpu"] = gq
			// ibq, _ := resource.ParseQuantity("1")
			// value["rdma/hca_rdma_infiniband"] = ibq
			patch = append(patch, patchOperation{
				Op:    "replace",
				Path:  fmt.Sprintf("/spec/containers/%d/resources/limits", i),
				Value: value,
			})

			patch = append(patch, patchOperation{
				Op:    "replace",
				Path:  fmt.Sprintf("/spec/containers/%d/resources/requests", i),
				Value: value,
			})
			// volume := t.VolumeMounts
			// volumeafter := []corev1.VolumeMount{}
			// for _, v := range volume {
			// 	if v.Name == "scratchvolume" {
			// 		m := corev1.MountPropagationHostToContainer
			// 		v.MountPropagation = &m
			// 		volumeafter = append(volumeafter, v)
			// 	} else if v.Name != "code" {
			// 		volumeafter = append(volumeafter, v)
			// 	}
			// }
			// patch = append(patch, patchOperation{
			// 	Op:    "replace",
			// 	Path:  fmt.Sprintf("/spec/containers/%d/volumeMounts", i),
			// 	Value: volumeafter,
			// })
			// t.SecurityContext.Privileged = &[]bool{true}[0]
			// patch = append(patch, patchOperation{
			// 	Op:    "replace",
			// 	Path:  fmt.Sprintf("/spec/containers/%d/securityContext", i),
			// 	Value: t.SecurityContext,
			// })
			// env := t.Env
			// env = append(env, corev1.EnvVar{
			// 	Name:  "AZUREML_COMPUTE_USE_COMMON_RUNTIME",
			// 	Value: "true",
			// })
			// patch = append(patch, patchOperation{
			// 	Op:    "replace",
			// 	Path:  fmt.Sprintf("/spec/containers/%d/env", i),
			// 	Value: env,
			// })
		}
		// else if t.Name == "sidecar" {
		// 	t.SecurityContext.Privileged = &[]bool{true}[0]
		// 	patch = append(patch, patchOperation{
		// 		Op:    "replace",
		// 		Path:  fmt.Sprintf("/spec/containers/%d/securityContext", i),
		// 		Value: t.SecurityContext,
		// 	})
		// 	// env := t.Env
		// 	// env = append(env, corev1.EnvVar{
		// 	// 	Name:  "AZUREML_COMPUTE_USE_COMMON_RUNTIME",
		// 	// 	Value: "true",
		// 	// })
		// 	// patch = append(patch, patchOperation{
		// 	// 	Op:    "replace",
		// 	// 	Path:  fmt.Sprintf("/spec/containers/%d/env", i),
		// 	// 	Value: env,
		// 	// })
		// 	volume := t.VolumeMounts
		// 	volumeafter := []corev1.VolumeMount{}
		// 	for _, v := range volume {
		// 		if v.Name == "scratchvolume" {
		// 			m := corev1.MountPropagationBidirectional
		// 			v.MountPropagation = &m
		// 		}
		// 		volumeafter = append(volumeafter, v)
		// 	}
		// 	patch = append(patch, patchOperation{
		// 		Op:    "replace",
		// 		Path:  fmt.Sprintf("/spec/containers/%d/volumeMounts", i),
		// 		Value: volumeafter,
		// 	})
		// } else if t.Name == "diagnostics" {
		// 	value := t.Resources.Limits
		// 	q, _ := resource.ParseQuantity("1")
		// 	value["cpu"] = q
		// 	// gq, _ := resource.ParseQuantity("1")
		// 	// value["nvidia.com/gpu"] = gq
		// 	// ibq, _ := resource.ParseQuantity("1")
		// 	// value["rdma/hca_rdma_infiniband"] = ibq
		// 	patch = append(patch, patchOperation{
		// 		Op:    "replace",
		// 		Path:  fmt.Sprintf("/spec/containers/%d/resources/limits", i),
		// 		Value: value,
		// 	})

		// 	t.SecurityContext.Privileged = &[]bool{true}[0]
		// 	patch = append(patch, patchOperation{
		// 		Op:    "replace",
		// 		Path:  fmt.Sprintf("/spec/containers/%d/securityContext", i),
		// 		Value: t.SecurityContext,
		// 	})
		// 	volume := t.VolumeMounts
		// 	m := corev1.MountPropagationHostToContainer
		// 	volume = append(volume, corev1.VolumeMount{
		// 		Name:             "sys",
		// 		MountPath:        "/host/sys",
		// 		ReadOnly:         true,
		// 		MountPropagation: &m,
		// 	})
		// 	patch = append(patch, patchOperation{
		// 		Op:    "replace",
		// 		Path:  fmt.Sprintf("/spec/containers/%d/volumeMounts", i),
		// 		Value: volume,
		// 	})
		// }
		// else if t.Name == "proxy" {
		// 	env := t.Env
		// 	env = append(env, corev1.EnvVar{
		// 		Name: "Fabric_NodeIPOrFQDN",
		// 		ValueFrom: &corev1.EnvVarSource{
		// 			FieldRef: &corev1.ObjectFieldSelector{
		// 				FieldPath: "status.hostIP",
		// 			},
		// 		},
		// 	})
		// 	patch = append(patch, patchOperation{
		// 		Op:    "replace",
		// 		Path:  fmt.Sprintf("/spec/containers/%d/env", i),
		// 		Value: env,
		// 	})
		// }

		env := t.Env
		env = append(env, corev1.EnvVar{
			Name:  "SINGULARITY_DISABLE_PUBLIC_NETWORKING_CHECK",
			Value: "true",
		})
		// env = append(env, corev1.EnvVar{
		// 	Name:  "AMD_VISIBLE_DEVICES",
		// 	Value: "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15",
		// })
		patch = append(patch, patchOperation{
			Op:    "replace",
			Path:  fmt.Sprintf("/spec/containers/%d/env", i),
			Value: env,
		})
	}
	return patch
}

func updateAnnotation(target map[string]string, added map[string]string) (patch []patchOperation) {
	for key, value := range added {
		if target == nil {
			target = map[string]string{}
		}
		target[key] = value
	}

	patch = append(patch, patchOperation{
		Op:    "replace",
		Path:  "/metadata/annotations",
		Value: target,
	})
	return patch
}

func updateVolume(target []corev1.Volume) (patch []patchOperation) {
	replaced := target
	// for _, value := range target {
	// 	if value.Name != "scratchvolume" && value.Name != "code" {
	// 		replaced = append(replaced, value)
	// 	}
	// }
	// replaced = append(replaced, corev1.Volume{
	// 	Name: "scratchvolume",
	// 	VolumeSource: corev1.VolumeSource{
	// 		EmptyDir: &corev1.EmptyDirVolumeSource{},
	// 	},
	// })
	replaced = append(replaced, corev1.Volume{
		Name: "sys",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/sys",
			},
		},
	})
	patch = append(patch, patchOperation{
		Op:    "replace",
		Path:  "/spec/volumes",
		Value: replaced,
	})
	return patch
}

func updateImagePullSecrets() (patch []patchOperation) {
	patch = append(patch, patchOperation{
		Op:   "add",
		Path: "/spec/imagePullSecrets",
		Value: []corev1.LocalObjectReference{
			{Name: "prejobacr05-pull-secret"},
			{Name: "user-acr-pull-secret"},
		},
	})
	return patch
}

func createSecret(namespace string) {
	kubeconfig := os.Getenv("KUBECONFIG")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		infoLogger.Printf("Error building kubeconfig: %s", err.Error())
		return
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		infoLogger.Printf("Error building kubernetes clientset: %s", err.Error())
		return
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prejobacr05-pull-secret",
			Namespace: namespace,
		},
		StringData: map[string]string{
			".dockerconfigjson": "eyJhdXRocyI6eyJwcmVqb2JhY3IwNS5henVyZWNyLmlvIjp7ImF1dGgiOiJjSEpsYW05aVlXTnlNRFU2Um5WWGEwVXhPSGRHWTBOc1FqUTVkeTl3WTFjdk5sazVhbnBzZEZneVQyWkhXbGx0UmtReFEwNUlLMEZEVWtGVlVHVnNNZz09In19fQ==",
		},
	}
	_, err = clientset.CoreV1().Secrets(namespace).Get(context.TODO(), "prejobacr05-pull-secret", metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		infoLogger.Printf("Created prejobacr05-pull-secret")
		_, err := clientset.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
		if err != nil {
			infoLogger.Printf("Failed to create prejobacr05-pull-secret: %s", err.Error())
		}
	} else if err != nil {
		warningLogger.Printf("Failed to get prejobacr05-pull-secret: %s", err.Error())
	}
}

// create mutation patch for resoures
func createPatch(pod *corev1.Pod) ([]byte, error) {
	var patch []patchOperation
	infoLogger.Printf("createPatch %s", pod.Name)

	//patch = append(patch, addContainerResource(pod.Spec.InitContainers)...)
	patch = append(patch, addContainerResource(pod.Spec.Containers)...)
	// annotations := map[string]string{"k8s.v1.cni.cncf.io/networks": "[{ \"name\": \"ib-rdma-sriov\", \"namespace\": \"kube-system\"}, { \"name\": \"ib-rdma-sriov\", \"namespace\": \"kube-system\"}]"}
	// patch = append(patch, updateAnnotation(pod.Annotations, annotations)...)
	//patch = append(patch, updateVolume(pod.Spec.Volumes)...)
	patch = append(patch, updateImagePullSecrets()...)
	createSecret(pod.Namespace)

	return json.Marshal(patch)
}

// main mutation process
func (whsvr *WebhookServer) mutate(ar *admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	req := ar.Request
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		warningLogger.Printf("Could not unmarshal raw object: %v", err)
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	infoLogger.Printf("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, pod.Name, req.UID, req.Operation, req.UserInfo)

	// determine whether to perform mutation
	// if !mutationRequired(ignoredNamespaces, &pod.ObjectMeta) {
	// 	infoLogger.Printf("Skipping mutation for %s/%s due to policy check", pod.Namespace, pod.Name)
	// 	return &admissionv1.AdmissionResponse{
	// 		Allowed: true,
	// 	}
	// }

	patchBytes, err := createPatch(&pod)
	if err != nil {
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	infoLogger.Printf("AdmissionResponse: patch=%v\n", string(patchBytes))
	return &admissionv1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *admissionv1.PatchType {
			pt := admissionv1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

// Serve method for webhook server
func (whsvr *WebhookServer) serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		warningLogger.Println("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		warningLogger.Printf("Content-Type=%s, expect application/json", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var admissionResponse *admissionv1.AdmissionResponse
	ar := admissionv1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		warningLogger.Printf("Can't decode body: %v", err)
		admissionResponse = &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse = whsvr.mutate(&ar)
	}

	admissionReview := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
	}
	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		if ar.Request != nil {
			admissionReview.Response.UID = ar.Request.UID
		}
	}

	resp, err := json.Marshal(admissionReview)
	if err != nil {
		warningLogger.Printf("Can't encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	infoLogger.Printf("Ready to write reponse ...")
	if _, err := w.Write(resp); err != nil {
		warningLogger.Printf("Can't write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}
