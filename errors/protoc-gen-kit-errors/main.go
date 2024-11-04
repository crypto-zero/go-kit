package main

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/iancoleman/strcase"

	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/pluginpb"

	pberrors "github.com/crypto-zero/go-kit/proto/kit/errors/v1"
)

// depart
var errorsPackage = protogen.GoImportPath("github.com/crypto-zero/go-kit/errors")

func main() {
	opts := protogen.Options{}
	opts.Run(
		func(plugin *protogen.Plugin) error {
			// set the supported features for proto3 optional
			plugin.SupportedFeatures = uint64(pluginpb.CodeGeneratorResponse_FEATURE_PROTO3_OPTIONAL)
			return NewGenerateErrorDeclare(plugin).Run()
		},
	)
}

type GenerateErrorDeclare struct {
	plugin *protogen.Plugin
}

func NewGenerateErrorDeclare(plugin *protogen.Plugin) *GenerateErrorDeclare {
	return &GenerateErrorDeclare{plugin: plugin}
}

func (g *GenerateErrorDeclare) Run() error {
	for _, f := range g.plugin.Files {
		if !f.Generate {
			continue
		}
		inputValues := make(map[*protogen.EnumValue]*pberrors.EnumErrorDetail)
		for _, e := range f.Enums {
			for _, ev := range e.Values {
				extDetail := proto.GetExtension(ev.Desc.Options(), pberrors.E_ErrorDetail)
				if extDetail == nil {
					continue
				}
				detail, ok := extDetail.(*pberrors.EnumErrorDetail)
				if !ok || detail == nil {
					continue
				}
				if detail.Code > 0 {
					inputValues[ev] = detail
				}
			}
		}
		if len(inputValues) == 0 {
			continue
		}
		if err := g.generateFile(f, inputValues); err != nil {
			return err
		}
	}
	return nil
}

func (g *GenerateErrorDeclare) generateFile(
	f *protogen.File,
	values map[*protogen.EnumValue]*pberrors.EnumErrorDetail,
) error {
	type enumValue struct {
		Value  *protogen.EnumValue
		Detail *pberrors.EnumErrorDetail
	}
	var enumValues []enumValue
	for ev, ext := range values {
		enumValues = append(enumValues, enumValue{Value: ev, Detail: ext})
	}
	slices.SortFunc(
		enumValues, func(a, b enumValue) int {
			return int(a.Value.Desc.Number() - b.Value.Desc.Number())
		},
	)

	filename := strings.TrimSuffix(f.Desc.Path(), filepath.Ext(f.Desc.Path())) + ".gen_errors.go"
	gf := g.plugin.NewGeneratedFile(filename, f.GoImportPath)

	gf.P("// Code generated by protoc-gen-kit-errors. DO NOT EDIT.")
	gf.P()
	gf.P("package ", f.GoPackageName)
	gf.P()

	strcase.ConfigureAcronym("CMS", "cms")
	for _, item := range enumValues {
		ev, ext := item.Value, item.Detail
		parentGoName := ev.Parent.GoIdent.GoName
		parentDescName := strcase.ToSnake(string(ev.Parent.Desc.Name()))
		parentDescName = strings.ToUpper(parentDescName)

		reason := strings.TrimPrefix(string(ev.Desc.Name()), parentDescName+"_")

		varName := strings.TrimPrefix(ev.GoIdent.GoName, parentGoName+"_")
		varNameV1 := strcase.ToCamel(varName)

		sinkVarName := varName
		lowSinkName, lowParentName := strings.ToLower(sinkVarName), strings.ToLower(parentDescName)
		if strings.HasPrefix(lowSinkName, lowParentName) {
			lowSinkName = strings.TrimPrefix(lowSinkName, lowParentName)
		}
		sinkVarName = "Err" + strcase.ToCamel(lowSinkName)

		gf.P(strings.TrimSpace(ev.Comments.Leading.String()))
		gf.P(
			"var ", sinkVarName, " = ",
			gf.QualifiedGoIdent(errorsPackage.Ident("New")),
			"(", int(ext.Code), ",",
			"\"", reason, "\",",
			"\"", ext.Message, "\"", ")",
			".SetDomainAndCode(\"", f.Proto.GetPackage(), "\", ", ev.Desc.Number(), ")",
		)

		gf.P(strings.TrimSpace(ev.Comments.Leading.String()))
		gf.P("// Deprecated: Use ", sinkVarName, " instead.")
		gf.P("var ", varNameV1, " = ", sinkVarName)
	}
	return nil
}
