import { Input, toast } from '@affine/component';
import { WorkspaceAvatar } from '@affine/component/workspace-avatar';
import { useAFFiNEI18N } from '@affine/i18n/hooks';
import { DoneIcon } from '@blocksuite/icons';
import { IconButton } from '@toeverything/components/button';
import { useBlockSuiteWorkspaceAvatarUrl } from '@toeverything/hooks/use-block-suite-workspace-avatar-url';
import { useBlockSuiteWorkspaceName } from '@toeverything/hooks/use-block-suite-workspace-name';
import { useCallback, useState } from 'react';

import type { AffineOfficialWorkspace } from '../../../shared';
import { Upload } from '../../pure/file-upload';
import * as style from './style.css';

const CameraIcon = () => {
  return (
    <svg
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M10.6236 4.25001C10.635 4.25001 10.6467 4.25002 10.6584 4.25002H13.3416C13.3533 4.25002 13.365 4.25001 13.3764 4.25001C13.5609 4.24995 13.7105 4.2499 13.8543 4.26611C14.5981 4.34997 15.2693 4.75627 15.6826 5.38026C15.7624 5.50084 15.83 5.63398 15.9121 5.79586C15.9173 5.80613 15.9226 5.81652 15.9279 5.82703C15.9538 5.87792 15.9679 5.90562 15.9789 5.9261C15.9832 5.9341 15.9857 5.93861 15.9869 5.94065C16.0076 5.97069 16.0435 5.99406 16.0878 5.99905L16.0849 5.99877C16.0849 5.99877 16.0907 5.99918 16.1047 5.99947C16.1286 5.99998 16.1604 6.00002 16.2181 6.00002L17.185 6.00001C17.6577 6 18.0566 5.99999 18.3833 6.02627C18.7252 6.05377 19.0531 6.11364 19.3656 6.27035C19.8402 6.50842 20.2283 6.88944 20.4723 7.36077C20.6336 7.67233 20.6951 7.99944 20.7232 8.33858C20.75 8.66166 20.75 9.05554 20.75 9.51992V16.2301C20.75 16.6945 20.75 17.0884 20.7232 17.4114C20.6951 17.7506 20.6336 18.0777 20.4723 18.3893C20.2283 18.8606 19.8402 19.2416 19.3656 19.4797C19.0531 19.6364 18.7252 19.6963 18.3833 19.7238C18.0566 19.75 17.6578 19.75 17.185 19.75H6.81497C6.34225 19.75 5.9434 19.75 5.61668 19.7238C5.27477 19.6963 4.94688 19.6364 4.63444 19.4797C4.15978 19.2416 3.77167 18.8606 3.52771 18.3893C3.36644 18.0777 3.30494 17.7506 3.27679 17.4114C3.24998 17.0884 3.24999 16.6945 3.25 16.2302V9.51987C3.24999 9.05551 3.24998 8.66164 3.27679 8.33858C3.30494 7.99944 3.36644 7.67233 3.52771 7.36077C3.77167 6.88944 4.15978 6.50842 4.63444 6.27035C4.94688 6.11364 5.27477 6.05377 5.61668 6.02627C5.9434 5.99999 6.34225 6 6.81498 6.00001L7.78191 6.00002C7.83959 6.00002 7.87142 5.99998 7.8953 5.99947C7.90607 5.99924 7.91176 5.99897 7.91398 5.99884C7.95747 5.99343 7.99267 5.9703 8.01312 5.94066C8.01429 5.93863 8.01684 5.93412 8.02113 5.9261C8.0321 5.90561 8.04622 5.87791 8.07206 5.82703C8.07739 5.81653 8.08266 5.80615 8.08787 5.79588C8.17004 5.63397 8.23759 5.50086 8.31745 5.38026C8.73067 4.75627 9.40192 4.34997 10.1457 4.26611C10.2895 4.2499 10.4391 4.24995 10.6236 4.25001ZM10.6584 5.75002C10.422 5.75002 10.3627 5.75114 10.3138 5.75666C10.0055 5.79142 9.73316 5.95919 9.56809 6.20845C9.54218 6.24758 9.51544 6.29761 9.40943 6.50633C9.40611 6.51287 9.40274 6.5195 9.39934 6.52622C9.36115 6.60161 9.31758 6.68761 9.26505 6.76694C8.9964 7.17261 8.56105 7.4354 8.08026 7.48961C7.98625 7.50021 7.89021 7.50011 7.80434 7.50003C7.79678 7.50002 7.7893 7.50002 7.78191 7.50002H6.84445C6.33444 7.50002 5.99634 7.50058 5.73693 7.52144C5.48594 7.54163 5.37478 7.57713 5.30693 7.61115C5.11257 7.70864 4.95675 7.86306 4.85983 8.05029C4.82733 8.11308 4.79194 8.21816 4.77165 8.46266C4.7506 8.71626 4.75 9.0474 4.75 9.55001V16.2C4.75 16.7026 4.7506 17.0338 4.77165 17.2874C4.79194 17.5319 4.82733 17.6369 4.85983 17.6997C4.95675 17.887 5.11257 18.0414 5.30693 18.1389C5.37478 18.1729 5.48594 18.2084 5.73693 18.2286C5.99634 18.2494 6.33444 18.25 6.84445 18.25H17.1556C17.6656 18.25 18.0037 18.2494 18.2631 18.2286C18.5141 18.2084 18.6252 18.1729 18.6931 18.1389C18.8874 18.0414 19.0433 17.887 19.1402 17.6997C19.1727 17.6369 19.2081 17.5319 19.2283 17.2874C19.2494 17.0338 19.25 16.7026 19.25 16.2V9.55001C19.25 9.0474 19.2494 8.71626 19.2283 8.46266C19.2081 8.21816 19.1727 8.11308 19.1402 8.05029C19.0433 7.86306 18.8874 7.70864 18.6931 7.61115C18.6252 7.57713 18.5141 7.54163 18.2631 7.52144C18.0037 7.50058 17.6656 7.50002 17.1556 7.50002H16.2181C16.2107 7.50002 16.2032 7.50002 16.1957 7.50003C16.1098 7.50011 16.0138 7.50021 15.9197 7.48961C15.4389 7.4354 15.0036 7.17261 14.735 6.76694C14.6824 6.68761 14.6389 6.60163 14.6007 6.52622C14.5973 6.5195 14.5939 6.51287 14.5906 6.50633C14.4846 6.29763 14.4578 6.24758 14.4319 6.20846C14.2668 5.95919 13.9945 5.79142 13.6862 5.75666C13.6373 5.75114 13.578 5.75002 13.3416 5.75002H10.6584ZM12 11C10.9303 11 10.0833 11.8506 10.0833 12.875C10.0833 13.8995 10.9303 14.75 12 14.75C13.0697 14.75 13.9167 13.8995 13.9167 12.875C13.9167 11.8506 13.0697 11 12 11ZM8.58333 12.875C8.58333 11 10.1242 9.50002 12 9.50002C13.8758 9.50002 15.4167 11 15.4167 12.875C15.4167 14.7501 13.8758 16.25 12 16.25C10.1242 16.25 8.58333 14.7501 8.58333 12.875Z"
        fill="white"
      />
    </svg>
  );
};

interface ProfilePanelProps {
  workspace: AffineOfficialWorkspace;
}

export const ProfilePanel = ({ workspace }: ProfilePanelProps) => {
  const t = useAFFiNEI18N();

  const [, update] = useBlockSuiteWorkspaceAvatarUrl(
    workspace.blockSuiteWorkspace
  );

  const [name, setName] = useBlockSuiteWorkspaceName(
    workspace.blockSuiteWorkspace
  );

  const [input, setInput] = useState<string>(name);

  const handleUpdateWorkspaceName = useCallback(
    (name: string) => {
      setName(name);
      toast(t['Update workspace name success']());
    },
    [setName, t]
  );

  return (
    <div className={style.profileWrapper}>
      <div className={style.avatarWrapper}>
        <Upload
          accept="image/gif,image/jpeg,image/jpg,image/png,image/svg"
          fileChange={update}
          data-testid="upload-avatar"
        >
          <>
            <div className="camera-icon-wrapper">
              <CameraIcon />
            </div>
            <WorkspaceAvatar
              size={56}
              workspace={workspace.blockSuiteWorkspace}
            />
          </>
        </Upload>
      </div>
      <div className={style.profileHandlerWrapper}>
        <Input
          width={280}
          height={32}
          defaultValue={input}
          data-testid="workspace-name-input"
          placeholder={t['Workspace Name']()}
          maxLength={64}
          minLength={0}
          onChange={setInput}
        />
        {input === workspace.blockSuiteWorkspace.meta.name ? null : (
          <IconButton
            data-testid="save-workspace-name"
            onClick={() => {
              handleUpdateWorkspaceName(input);
            }}
            active={true}
            style={{
              marginLeft: '12px',
            }}
          >
            <DoneIcon />
          </IconButton>
        )}
      </div>
    </div>
  );
};